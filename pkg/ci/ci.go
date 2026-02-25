package ci

// Metadata holds CI build context included in every cloud upload.
type Metadata struct {
	Provider   string `json:"provider"`
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`
	PRNumber   string `json:"pr_number,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	RunURL     string `json:"run_url,omitempty"`
	Actor      string `json:"actor,omitempty"`
	EventName  string `json:"event_name,omitempty"`
}

// Provider detects a CI system and extracts metadata.
type Provider interface {
	Name() string
	Detect() bool
	GetMetadata() Metadata
}

var registry []Provider

// Register adds a CI provider to the detection registry.
func Register(p Provider) { registry = append(registry, p) }

// Detect returns metadata from the first matching provider, or nil.
func Detect() *Metadata {
	for _, p := range registry {
		if p.Detect() {
			m := p.GetMetadata()
			return &m
		}
	}
	return nil
}
