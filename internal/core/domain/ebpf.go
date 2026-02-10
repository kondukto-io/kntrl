package domain

// EBPFCollectionMapMode is the mode of the EBPF collection map
const EBPFCollectionMapMode = "mode_map"

// EBPFCollectionMapAllowedIP is the allow list of the EBPF collection map
const EBPFCollectionMapAllowedIP = "allowed_ip_map"

// EBPFCollectionMapAllowedHost is the allow list of the EBPF collection map
const EBPFCollectionMapAllowedHost = "allowed_hosts_map"

// EBPFCollectionMapIPV4Events is the IPv4 events ring buffer of the EBPF collection map
const EBPFCollectionMapIPV4Events = "ipv4_events"

// EBPFCollectionMapIPV6Events is the IPv6 events ring buffer
const EBPFCollectionMapIPV6Events = "ipv6_events"

// EBPFCollectionMapAllowedIPv6 is the allow list for IPv6 addresses
const EBPFCollectionMapAllowedIPv6 = "allowed_ipv6_map"

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
