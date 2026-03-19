//go:build ignore

#include "headers/vmlinux.h"
/* vmlinux.h provides bool (_Bool) and all kernel types.
 * Do NOT include libc headers (stdbool.h, string.h, errno.h, etc.)
 * — they pull in arch-specific paths that break -target bpf builds. */

#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"
#include "headers/dns.h"

#include "sensor_defs.h"
#include "sensor_helpers.h"
#include "sensor_network.h"
#include "sensor_dns.h"
#include "sensor_process.h"
#include "sensor_file.h"
#include "sensor_sni.h"
#include "sensor_cgroup.h"

char __license[] SEC("license") = "GPL";
