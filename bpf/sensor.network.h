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
