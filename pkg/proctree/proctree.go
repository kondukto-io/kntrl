package proctree

import "sync"

type processInfo struct {
	ppid uint32
	comm string
}

// ProcessTree maintains an in-memory process tree built from fork/exec events.
type ProcessTree struct {
	mu    sync.RWMutex
	procs map[uint32]processInfo
}

// New creates a new ProcessTree.
func New() *ProcessTree {
	return &ProcessTree{
		procs: make(map[uint32]processInfo),
	}
}

// Update records a process with its parent and command name.
func (t *ProcessTree) Update(pid, ppid uint32, comm string) {
	t.mu.Lock()
	t.procs[pid] = processInfo{ppid: ppid, comm: comm}
	t.mu.Unlock()
}

// GetAncestors walks the process tree from pid's parent upward,
// collecting command names. Stops at max depth, missing entry, pid 0, or cycle.
func (t *ProcessTree) GetAncestors(pid uint32, maxDepth int) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var ancestors []string
	seen := make(map[uint32]struct{})
	current := pid

	for i := 0; i < maxDepth; i++ {
		info, ok := t.procs[current]
		if !ok || info.ppid == 0 {
			break
		}
		if _, cycle := seen[info.ppid]; cycle {
			break
		}
		seen[current] = struct{}{}
		parent, ok := t.procs[info.ppid]
		if !ok {
			break
		}
		ancestors = append(ancestors, parent.comm)
		current = info.ppid
	}

	return ancestors
}
