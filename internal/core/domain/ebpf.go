package domain

// EBPFCollectionMapMode is the mode of the EBPF collection map
const EBPFCollectionMapMode = "mode_map"

// EBPFCollectionMapConnections holds socket-scoped policy grants.
const EBPFCollectionMapConnections = "allowed_connections"

const EBPFCollectionMapDNSResolvers = "dns_resolvers"

// EBPFCollectionMapAllowedHost is the allow list of the EBPF collection map
const EBPFCollectionMapAllowedHost = "allowed_hosts_map"

// EBPFCollectionMapIPV4Events is the IPv4 events ring buffer of the EBPF collection map
const EBPFCollectionMapIPV4Events = "ipv4_events"

// EBPFCollectionMapIPV6Events is the IPv6 events ring buffer
const EBPFCollectionMapIPV6Events = "ipv6_events"

// EBPFCollectionMapSNIEvents is the TLS SNI events ring buffer
const EBPFCollectionMapSNIEvents = "sni_events"

// EBPFCollectionMapDNSEvents is the DNS events ring buffer
const EBPFCollectionMapDNSEvents = "dns_events"

// EBPFCollectionMapAllowedDNSServers is the allowed DNS servers map
const EBPFCollectionMapAllowedDNSServers = "allowed_dns_servers_map"

// EBPFCollectionMapProcessEvents is the process events ring buffer
const EBPFCollectionMapProcessEvents = "process_events"

// EBPFCollectionMapProcessMonitor is the process monitoring enable/disable flag
const EBPFCollectionMapProcessMonitor = "process_monitor_map"

// EBPFCollectionMapFileEvents is the file events ring buffer
const EBPFCollectionMapFileEvents = "file_events"

// EBPFCollectionMapFileMonitor is the file monitoring enable/disable flag
const EBPFCollectionMapFileMonitor = "file_monitor_map"

// EBPFCollectionMapSelfTGID holds kntrl's own TGID for BPF-level self-filtering
const EBPFCollectionMapSelfTGID = "self_tgid_map"

// EBPFCollectionMapBlockedExec is the hash map of executable names to block
const EBPFCollectionMapBlockedExec = "blocked_exec_map"

// EBPFCollectionMapProtectedPaths is the hash map of paths to protect from writes
const EBPFCollectionMapProtectedPaths = "protected_paths_map"
