/**
 * This example copies parts of struct sock_common and struct sock from
 * the Linux kernel, but doesn't cause any CO-RE information to be emitted
 * into the ELF object. This requires the struct layout (up until the fields
 * that are being accessed) to match the kernel's, and the example will break
 * or misbehave when this is no longer the case.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};

typedef unsigned short int sa_family_t;

struct sockaddr
{
  sa_family_t sa_family;
  char sa_data[14];
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};


struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

struct trace_event_sys_enter_connect
{
  struct trace_entry ent;
  int __syscall_nr;
  long unsigned int fd;
  struct sockaddr *uservaddr;
  long unsigned int addrlen;
};


#define EVENT_TCP_ESTABLISHED	1
#define EVENT_TCP_CONNECT_FAILED		2
#define EVENT_TCP_LISTEN	3
#define EVENT_TCP_LISTEN_CLOSED	4
#define EVENT_TCP_CLOSED	5

#define IPPROTO_TCP             6               /* Transmission Control Protocol    */
#define IPPROTO_UDP             17              /* User Datagram Protocol        */

