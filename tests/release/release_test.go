package release

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

type job struct {
	Needs       string            `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []step            `yaml:"steps"`
}

type step struct {
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Shell           string            `yaml:"shell"`
	If              string            `yaml:"if"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	Directory       string            `yaml:"working-directory"`
	Env             map[string]string `yaml:"env"`
	With            map[string]string `yaml:"with"`
}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	data, err := os.ReadFile("../../.github/workflows/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func findStep(t *testing.T, w workflow, name string) (int, step) {
	t.Helper()
	for i, s := range w.Jobs["publish"].Steps {
		if s.Name == name {
			return i, s
		}
	}
	t.Fatalf("missing publishing step %q", name)
	return 0, step{}
}

func TestSigningTrustBoundary(t *testing.T) {
	w := loadWorkflow(t)
	if w.Permissions["id-token"] == "write" || w.Permissions["contents"] != "read" {
		t.Fatal("workflow must default to read-only without OIDC")
	}
	for name, j := range w.Jobs {
		if name != "publish" && (j.Permissions["id-token"] == "write" || j.Permissions["contents"] == "write") {
			t.Fatalf("%s has signing or publishing credentials", name)
		}
	}
	if w.Jobs["publish"].Permissions["id-token"] != "write" ||
		w.Jobs["publish"].Needs != "build" || w.Jobs["build"].Needs != "verify" {
		t.Fatal("signing must follow verification and the isolated build")
	}
	for _, s := range w.Jobs["publish"].Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") || s.ContinueOnError || s.If != "" {
			t.Fatalf("publishing must not check out project code or bypass a failed step: %s", s.Name)
		}
	}
}

func TestSignaturePublicationContract(t *testing.T) {
	w := loadWorkflow(t)
	validateIndex, validate := findStep(t, w, "Validate assets before signing")
	signIndex, sign := findStep(t, w, "Sign and verify checksum manifest")
	publishIndex, publish := findStep(t, w, "Publish existing tag")
	if !(validateIndex < signIndex && signIndex < publishIndex) {
		t.Fatal("assets must be validated and signatures verified before publication")
	}
	if validate.Shell != "bash" || sign.Shell != "bash" {
		t.Fatal("security steps must explicitly use bash with GitHub's pipefail behavior")
	}
	if sign.Env["RELEASE_IDENTITY"] != "https://github.com/${{ github.repository }}/.github/workflows/release.yaml@${{ github.ref }}" {
		t.Fatal("verification identity must bind the release workflow and exact ref")
	}
	if !strings.Contains(publish.Run, "release/checksums.txt.sigstore.json") {
		t.Fatal("release must include the signature bundle")
	}
	_, install := findStep(t, w, "Install Cosign")
	if !regexp.MustCompile(`^sigstore/cosign-installer@[0-9a-f]{40}$`).MatchString(install.Uses) ||
		!regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(install.With["cosign-release"]) {
		t.Fatal("Cosign installer and binary version must be pinned")
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func releaseFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "release")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	// Deliberately reversed: GoReleaser's manifest order is not a trust boundary.
	for _, name := range []string{"kntrl_arm64.arm64", "kntrl.amd64"} {
		writeFile(t, filepath.Join(dir, name), name, 0600)
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256([]byte(name)), name)
	}
	writeFile(t, filepath.Join(dir, "checksums.txt"), manifest.String(), 0600)
	return root
}

func runStep(t *testing.T, root string, s step, env ...string) error {
	t.Helper()
	cmd := exec.Command("bash", "-euo", "pipefail", "-c", s.Run)
	cmd.Dir = filepath.Join(root, s.Directory)
	cmd.Env = append(os.Environ(), "RUNNER_TEMP="+root)
	cmd.Env = append(cmd.Env, env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}

func TestRejectUntrustedReleaseAssets(t *testing.T) {
	_, validate := findStep(t, loadWorkflow(t), "Validate assets before signing")
	for _, scenario := range []string{"valid", "tampered binary", "missing binary", "extra manifest entry", "duplicate entry", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root := releaseFixture(t)
			dir := filepath.Join(root, "release")
			binary := filepath.Join(dir, "kntrl.amd64")
			manifest := filepath.Join(dir, "checksums.txt")
			switch scenario {
			case "tampered binary":
				writeFile(t, binary, "tampered", 0600)
			case "missing binary", "symlink":
				if err := os.Remove(binary); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink" {
					writeFile(t, filepath.Join(root, "outside"), "kntrl.amd64", 0600)
					if err := os.Symlink("../outside", binary); err != nil {
						t.Fatal(err)
					}
				}
			case "extra manifest entry", "duplicate entry":
				data, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				entry := fmt.Sprintf("%x  ../outside\n", sha256.Sum256(nil))
				if scenario == "duplicate entry" {
					entry = strings.SplitN(string(data), "\n", 2)[0] + "\n"
				}
				writeFile(t, manifest, string(data)+entry, 0600)
			}
			if err := runStep(t, root, validate); (err == nil) != (scenario == "valid") {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}

func TestSigningFailsClosed(t *testing.T) {
	_, sign := findStep(t, loadWorkflow(t), "Sign and verify checksum manifest")
	const identity = "https://github.com/kondukto-io/kntrl/.github/workflows/release.yaml@refs/tags/v0.3.0"
	for _, fail := range []string{"", "sign-blob", "verify-blob"} {
		t.Run("fail="+fail, func(t *testing.T) {
			root := releaseFixture(t)
			logPath := filepath.Join(root, "cosign.log")
			writeFile(t, filepath.Join(root, "cosign"), `#!/bin/bash
set -eu
printf '%s\n' "$@" >> "$COSIGN_LOG"
if test "$1" = "$FAIL_COMMAND"; then exit 42; fi
if test "$1" = sign-blob; then echo test-bundle > checksums.txt.sigstore.json; fi
`, 0700)
			err := runStep(t, root, sign, "PATH="+root+":"+os.Getenv("PATH"),
				"COSIGN_LOG="+logPath, "FAIL_COMMAND="+fail, "RELEASE_IDENTITY="+identity)
			if (err == nil) != (fail == "") {
				t.Fatalf("unexpected signing result: %v", err)
			}
			log, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			calls := string(log)
			if !strings.HasPrefix(calls, "sign-blob\n--yes\n--bundle\nchecksums.txt.sigstore.json\nchecksums.txt\n") {
				t.Fatalf("unexpected signing arguments: %s", calls)
			}
			if fail == "sign-blob" {
				if strings.Contains(calls, "verify-blob") {
					t.Fatal("execution continued after signing failed")
				}
			} else if !strings.Contains(calls, "verify-blob\n--bundle\nchecksums.txt.sigstore.json\n--certificate-identity\n"+identity+
				"\n--certificate-oidc-issuer\nhttps://token.actions.githubusercontent.com\nchecksums.txt\n") {
				t.Fatalf("verification must enforce issuer and exact identity: %s", calls)
			}
		})
	}
}
