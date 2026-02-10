package policy

import (
	"context"
	"encoding/json"
	"fmt"
	files "io/fs"
	"os"
	"strings"

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

// Policy struct to stores rego function
// as we add more queries additional (custom)
// rules other regoArgs may be required in the future
type Policy struct {
	regoArgs []func(r *rego.Rego)
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

// AddQuery is the query that will be executed
// in the main.rego
func (p *Policy) AddQuery(query string) {
	p.regoArgs = append(p.regoArgs, rego.Query(query))
}

// Eval evaluates the policy with the given input
func (p *Policy) Eval(ctx context.Context, input map[string]any) (bool, error) {
	query, err := rego.New(p.regoArgs...).PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	result, err := query.Eval(ctx, rego.EvalInput(input))
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

func (p *Policy) EvalEvent(ctx context.Context, event domain.ReportEvent) (bool, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	var outmap map[string]any
	json.Unmarshal(data, &outmap)

	return p.Eval(ctx, outmap)
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
