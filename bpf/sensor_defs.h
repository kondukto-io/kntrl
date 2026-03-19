#ifndef SENSOR_DEFS_H
#define SENSOR_DEFS_H

/* ========================
 * Constants
 * ======================== */

#define AF_INET 2
#define TASK_COMM_LEN 16
#define MAX_ENTIRES 1024
#define MAX_HOSTNAME_LEN 256
#define MAX_FILENAME_LEN 256
#define MODE_ALLOW 1

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

#define AF_INET6 10

#define MAX_ARGS_LEN 256

#define EVENT_TYPE_FORK 1
#define EVENT_TYPE_EXEC 2

#define AF_PACKET 17
#define IPPROTO_RAW 255
#define IPPROTO_ICMP 1

#define EVENT_FLAG_BLOCKED 1
#define MAX_BLOCKED_EXECS 64
#define MAX_PROTECTED_PATHS 64

#define O_WRONLY 1
#define O_RDWR   2
#define O_CREAT  0100
#define O_TRUNC  01000
#define O_APPEND 02000
#define WRITE_FLAGS_MASK (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)

#define FILE_OP_OPEN    0
#define FILE_OP_RENAME  1
#define FILE_OP_UNLINK  2
#define FILE_OP_ACCESS  3

/* ========================
 * Shared Map Definitions
 * ======================== */

/* Map for allowed IP addresses from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_ip_map SEC(".maps");

/* Map for allowed hostnames from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, MAX_HOSTNAME_LEN);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_hosts_map SEC(".maps");

/* Map to pass mode to filter function */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} mode_map SEC(".maps");

/* Map for allowed IPv6 addresses */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, 16);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTIRES);
} allowed_ipv6_map SEC(".maps");

/* Enable/disable flag for process monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} process_monitor_map SEC(".maps");

/* Enable/disable flag for file monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} file_monitor_map SEC(".maps");

/* Map holding kntrl's own TGID so BPF can drop self-generated events */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} self_tgid_map SEC(".maps");

/* Hash map of executable names to block unconditionally */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, TASK_COMM_LEN);
	__type(value, __u32);
	__uint(max_entries, MAX_BLOCKED_EXECS);
} blocked_exec_map SEC(".maps");

/* Hash map of exact paths to protect from writes */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_FILENAME_LEN);
	__type(value, __u32);
	__uint(max_entries, MAX_PROTECTED_PATHS);
} protected_paths_map SEC(".maps");

#endif /* SENSOR_DEFS_H */
