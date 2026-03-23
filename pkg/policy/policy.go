package policy

import (
	"context"
	"fmt"
	files "io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/loader/filter"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

const (
	bundleName = "kntrl"
)

// Option is a functional option for configuring Policy creation.
type Option func(*policyOptions)

type policyOptions struct {
	externalRegoFiles []string
}

// WithExternalRego adds external .rego file paths to be loaded alongside the bundle.
func WithExternalRego(paths []string) Option {
	return func(o *policyOptions) {
		o.externalRegoFiles = append(o.externalRegoFiles, paths...)
	}
}

const policyCacheTTL = 30 * time.Second

type policyCacheEntry struct {
	result    bool
	expiresAt time.Time
}

// Policy struct stores the pre-compiled OPA query for efficient repeated evaluation.
type Policy struct {
	regoArgs    []func(r *rego.Rego)
	prepared    *rego.PreparedEvalQuery
	policyCache sync.Map
}

// New creates a new Rego policy engine.
// fs is the embedded bundle FS, data is the configuration data,
// and opts allows loading external .rego files.
func New(fs files.FS, data []byte, opts ...Option) (*Policy, error) {
	ctx := context.Background()

	// Process options
	var popts policyOptions
	for _, o := range opts {
		o(&popts)
	}

	bundleClient, err := loadBundleFS(fs)
	if err != nil {
		return nil, err
	}

	dataJson, err := unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal data json: %w", err)
	}

	// load data objects inside 'assets' dir
	dataJson["assets"] = bundleClient.Data["assets"]

	store := inmem.NewFromObject(dataJson)
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return nil, err
	}

	var regoArgs []func(r *rego.Rego)
	regoArgs = append(
		regoArgs,
		rego.ParsedBundle(bundleName, &bundleClient),
		rego.Store(store),
		rego.Transaction(txn),
	)

	// Load external .rego files as additional modules
	for _, regoPath := range popts.externalRegoFiles {
		content, err := os.ReadFile(regoPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read external rego file %s: %w", regoPath, err)
		}
		regoArgs = append(regoArgs, rego.Module(regoPath, string(content)))
	}

	return &Policy{
		regoArgs: regoArgs,
	}, nil
}

// AddQuery sets the query and pre-compiles the policy for efficient evaluation.
func (p *Policy) AddQuery(query string) {
	p.regoArgs = append(p.regoArgs, rego.Query(query))

	// Pre-compile the query once for reuse across all evaluations
	ctx := context.Background()
	prepared, err := rego.New(p.regoArgs...).PrepareForEval(ctx)
	if err != nil {
		// Store nil; Eval will fall back to per-call compilation
		p.prepared = nil
		return
	}
	p.prepared = &prepared
}

// Eval evaluates the policy with the given input.
func (p *Policy) Eval(ctx context.Context, input map[string]any) (bool, error) {
	var result rego.ResultSet
	var err error

	if p.prepared != nil {
		result, err = p.prepared.Eval(ctx, rego.EvalInput(input))
	} else {
		// Fallback: compile on demand (should not happen in normal flow)
		query, prepErr := rego.New(p.regoArgs...).PrepareForEval(ctx)
		if prepErr != nil {
			return false, fmt.Errorf("failed to prepare rego query: %w", prepErr)
		}
		result, err = query.Eval(ctx, rego.EvalInput(input))
	}

	if err != nil {
		return false, fmt.Errorf("failed to eval rego query: %w", err)
	}

	if len(result) == 0 || len(result[0].Expressions) == 0 {
		return false, nil
	}

	val, ok := result[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected policy result type: %T", result[0].Expressions[0].Value)
	}

	return val, nil
}

// EvalEvent evaluates the policy against a ReportEvent by building the input map directly.
func (p *Policy) EvalEvent(ctx context.Context, event domain.ReportEvent) (bool, error) {
	input := map[string]any{
		"pid":       event.ProcessID,
		"task_name": event.TaskName,
		"proto":     event.Protocol,
		"daddr":     event.DestinationAddress,
		"dport":     event.DestinationPort,
		"domains":   event.Domains,
		"policy":    event.Policy,
	}
	if event.SNI != "" {
		input["sni"] = event.SNI
	}
	if len(event.Ancestors) > 0 {
		input["ancestors"] = event.Ancestors
	}

	return p.Eval(ctx, input)
}

// EvalEventCached evaluates the policy with caching.
// Cache key includes task name, destination, port, and ancestors to ensure
// ancestry-based rules (e.g. block python-from-npm) are evaluated correctly.
func (p *Policy) EvalEventCached(ctx context.Context, event domain.ReportEvent) (bool, error) {
	key := event.TaskName + "|" + event.DestinationAddress + "|" + fmt.Sprint(event.DestinationPort) + "|" + strings.Join(event.Ancestors, ",")

	if cached, ok := p.policyCache.Load(key); ok {
		entry := cached.(policyCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.result, nil
		}
		p.policyCache.Delete(key)
	}

	result, err := p.EvalEvent(ctx, event)
	if err != nil {
		return false, err
	}

	p.policyCache.Store(key, policyCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(policyCacheTTL),
	})

	return result, nil
}

// FlushCache clears the policy result cache. Called on SIGHUP reload.
func (p *Policy) FlushCache() {
	p.policyCache.Range(func(key, _ any) bool {
		p.policyCache.Delete(key)
		return true
	})
}

func unmarshal(data []byte) (dataJson map[string]any, err error) {
	if err = util.Unmarshal(data, &dataJson); err != nil {
		return dataJson, err
	}

	return dataJson, nil
}

// LoadBundleFS loads bundle embedded from policy and data directory.
func loadBundleFS(fs files.FS) (bundle.Bundle, error) {
	embedLoader, err := bundle.NewFSLoader(fs)
	if err != nil {
		return bundle.Bundle{}, fmt.Errorf("failed to load bundle from filesystem: %w", err)
	}

	return bundle.NewCustomReader(embedLoader.WithFilter(excludeTestFilter())).
		WithSkipBundleVerification(true).
		WithProcessAnnotations(true).
		WithBundleName(bundleName).
		Read()
}

func excludeTestFilter() filter.LoaderFilter {
	return func(_ string, info files.FileInfo, _ int) bool {
		return strings.HasSuffix(info.Name(), "_test.rego")
	}
}
