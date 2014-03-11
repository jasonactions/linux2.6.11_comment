/*
 * This is <linux/capability.h>
 *
 * Andrew G. Morgan <morgan@transmeta.com>
 * Alexander Kjeldaas <astor@guardian.no>
 * with help from Aleph1, Roland Buresund and Andrew Main.
 *
 * See here for the libcap library ("POSIX draft" compliance):
 *
 * ftp://linux.kernel.org/pub/linux/libs/security/linux-privs/kernel-2.2/
 */ 

#ifndef _LINUX_CAPABILITY_H
#define _LINUX_CAPABILITY_H

#include <linux/types.h>
#include <linux/compiler.h>

/* User-level do most of the mapping between kernel and user
   capabilities based on the version tag given by the kernel. The
   kernel might be somewhat backwards compatible, but don't bet on
   it. */

/* XXX - Note, cap_t, is defined by POSIX to be an "opaque" pointer to
   a set of three capability sets.  The transposition of 3*the
   following structure to such a composite is better handled in a user
   library since the draft standard requires the use of malloc/free
   etc.. */
 
#define _LINUX_CAPABILITY_VERSION  0x19980330

typedef struct __user_cap_header_struct {
	__u32 version;
	int pid;
} __user *cap_user_header_t;
 
typedef struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
} __user *cap_user_data_t;
  
#ifdef __KERNEL__

#include <linux/spinlock.h>

extern spinlock_t task_capability_lock;

/* #define STRICT_CAP_T_TYPECHECKS */

#ifdef STRICT_CAP_T_TYPECHECKS

typedef struct kernel_cap_struct {
	__u32 cap;
} kernel_cap_t;

#else

typedef __u32 kernel_cap_t;

#endif
  
#define _USER_CAP_HEADER_SIZE  (2*sizeof(__u32))
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#endif


/**
 ** POSIX-draft defined capabilities. 
 **/

/* In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this
   overrides the restriction of changing file ownership and group
   ownership. */

/**
 * 忽略对文件和组的拥有者进行改变的限制
 */
#define CAP_CHOWN            0

/* Override all DAC access, including ACL execute access if
   [_POSIX_ACL] is defined. Excluding DAC access covered by
   CAP_LINUX_IMMUTABLE. */

/**
 * 忽略文件的访问许可权
 */
#define CAP_DAC_OVERRIDE     1

/* Overrides all DAC restrictions regarding read and search on files
   and directories, including ACL restrictions if [_POSIX_ACL] is
   defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE. */

/**
 * 忽略文件/目录读和搜索的许可权
 */
#define CAP_DAC_READ_SEARCH  2
    
/* Overrides all restrictions about allowed operations on files, where
   file owner ID must be equal to the user ID, except where CAP_FSETID
   is applicable. It doesn't override MAC and DAC restrictions. */

/**
 * 一般是忽略对文件拥有者的权限检查
 */
#define CAP_FOWNER           3

/* Overrides the following restrictions that the effective user ID
   shall match the file owner ID when setting the S_ISUID and S_ISGID
   bits on that file; that the effective group ID (or one of the
   supplementary group IDs) shall match the file owner ID when setting
   the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are
   cleared on successful return from chown(2) (not implemented). */

/**
 * 忽略对文件setid和setgid标志设置的限制
 */
#define CAP_FSETID           4

/* Used to decide between falling back on the old suser() or fsuser(). */

#define CAP_FS_MASK          0x1f

/* Overrides the restriction that the real or effective user ID of a
   process sending a signal must match the real or effective user ID
   of the process receiving the signal. */

/**
 * 产生信号时绕过权限检查
 */
#define CAP_KILL             5

/* Allows setgid(2) manipulation */
/* Allows setgroups(2) */
/* Allows forged gids on socket credentials passing. */

/**
 * 忽略对组进程操作的限制
 */
#define CAP_SETGID           6

/* Allows set*uid(2) manipulation (including fsuid). */
/* Allows forged pids on socket credentials passing. */

/**
 * 忽略对用户进程操作的限制
 */
#define CAP_SETUID           7


/**
 ** Linux-specific capabilities
 **/

/* Transfer any capability in your permitted set to any pid,
   remove any capability in your permitted set from any pid */

/**
 * 允许对其他进程进行权能操作
 */
#define CAP_SETPCAP          8

/* Allow modification of S_IMMUTABLE and S_APPEND file attributes */

/**
 * 允许修改仅追加和不可变的Ext2/Ext3文件
 */
#define CAP_LINUX_IMMUTABLE  9

/* Allows binding to TCP/UDP sockets below 1024 */
/* Allows binding to ATM VCIs below 32 */

/**
 * 允许绑定到低于1024的TCP/UDP套接字
 */
#define CAP_NET_BIND_SERVICE 10

/* Allow broadcasting, listen to multicast */

/**
 * 允许广播与组播
 */
#define CAP_NET_BROADCAST    11

/* Allow interface configuration */
/* Allow administration of IP firewall, masquerading and accounting */
/* Allow setting debug option on sockets */
/* Allow modification of routing tables */
/* Allow setting arbitrary process / process group ownership on
   sockets */
/* Allow binding to any address for transparent proxying */
/* Allow setting TOS (type of service) */
/* Allow setting promiscuous mode */
/* Allow clearing driver statistics */
/* Allow multicasting */
/* Allow read/write of device-specific registers */
/* Allow activation of ATM control sockets */

/**
 * 允许一般的联网管理
 */
#define CAP_NET_ADMIN        12

/* Allow use of RAW sockets */
/* Allow use of PACKET sockets */

/**
 * 允许使用RAW和PACKET套接字
 */
#define CAP_NET_RAW          13

/* Allow locking of shared memory segments */
/* Allow mlock and mlockall (which doesn't really have anything to do
   with IPC) */

/**
 * 允许页加锁和共享内存段加锁
 */
#define CAP_IPC_LOCK         14

/* Override IPC ownership checks */

/**
 * 跳过IPC拥有者检查
 */
#define CAP_IPC_OWNER        15

/* Insert and remove kernel modules - modify kernel without limit */
/* Modify cap_bset */
/**
 * 允许插入和卸载模块
 */
#define CAP_SYS_MODULE       16

/* Allow ioperm/iopl access */
/* Allow sending USB messages to any device via /proc/bus/usb */

/**
 * 允许通过ioperm和iopl访问IO端口
 */
#define CAP_SYS_RAWIO        17

/* Allow use of chroot() */

/**
 * 允许使用chroot
 */
#define CAP_SYS_CHROOT       18

/* Allow ptrace() of any process */

/**
 * 允许对任何进程使用ptrace
 */
#define CAP_SYS_PTRACE       19

/* Allow configuration of process accounting */

/**
 * 允许配置进程记帐
 */
#define CAP_SYS_PACCT        20

/* Allow configuration of the secure attention key */
/* Allow administration of the random device */
/* Allow examination and configuration of disk quotas */
/* Allow configuring the kernel's syslog (printk behaviour) */
/* Allow setting the domainname */
/* Allow setting the hostname */
/* Allow calling bdflush() */
/* Allow mount() and umount(), setting up new smb connection */
/* Allow some autofs root ioctls */
/* Allow nfsservctl */
/* Allow VM86_REQUEST_IRQ */
/* Allow to read/write pci config on alpha */
/* Allow irix_prctl on mips (setstacksize) */
/* Allow flushing all cache on m68k (sys_cacheflush) */
/* Allow removing semaphores */
/* Used instead of CAP_CHOWN to "chown" IPC message queues, semaphores
   and shared memory */
/* Allow locking/unlocking of shared memory segment */
/* Allow turning swap on/off */
/* Allow forged pids on socket credentials passing */
/* Allow setting readahead and flushing buffers on block devices */
/* Allow setting geometry in floppy driver */
/* Allow turning DMA on/off in xd driver */
/* Allow administration of md devices (mostly the above, but some
   extra ioctls) */
/* Allow tuning the ide driver */
/* Allow access to the nvram device */
/* Allow administration of apm_bios, serial and bttv (TV) device */
/* Allow manufacturer commands in isdn CAPI support driver */
/* Allow reading non-standardized portions of pci configuration space */
/* Allow DDI debug ioctl on sbpcd driver */
/* Allow setting up serial ports */
/* Allow sending raw qic-117 commands */
/* Allow enabling/disabling tagged queuing on SCSI controllers and sending
   arbitrary SCSI commands */
/* Allow setting encryption key on loopback filesystem */

/**
 * 允许一般的系统管理
 */
#define CAP_SYS_ADMIN        21

/* Allow use of reboot() */

/**
 * 允许使用reboot
 */
#define CAP_SYS_BOOT         22

/* Allow raising priority and setting priority on other (different
   UID) processes */
/* Allow use of FIFO and round-robin (realtime) scheduling on own
   processes and setting the scheduling algorithm used by another
   process. */
/* Allow setting cpu affinity on other processes */

/**
 * 跳过nice和setpriority系统调用的权限检查，并允许创建实时进程。
 */
#define CAP_SYS_NICE         23

/* Override resource limits. Set resource limits. */
/* Override quota limits. */
/* Override reserved space on ext2 filesystem */
/* Modify data journaling mode on ext3 filesystem (uses journaling
   resources) */
/* NOTE: ext2 honors fsuid when checking for resource overrides, so 
   you can override using fsuid too */
/* Override size restrictions on IPC message queues */
/* Allow more than 64hz interrupts from the real-time clock */
/* Override max number of consoles on console allocation */
/* Override max number of keymaps */

/**
 * 允许增加资源限制
 */
#define CAP_SYS_RESOURCE     24

/* Allow manipulation of system clock */
/* Allow irix_stime on mips */
/* Allow setting the real-time clock */

/**
 * 允许系统时钟和实时时钟的操作
 */
#define CAP_SYS_TIME         25

/* Allow configuration of tty devices */
/* Allow vhangup() of tty */

/**
 * 允许配置终端并执行vhangup系统调用。
 */
#define CAP_SYS_TTY_CONFIG   26

/* Allow the privileged aspects of mknod() */

/**
 * 允许有特权的mknod操作
 */
#define CAP_MKNOD            27

/* Allow taking of leases on files */

/**
 * 允许对文件进行租借。
 */
#define CAP_LEASE            28

/**
 * 通过在netlink套接字进行写入而产生审计消息
 */
#define CAP_AUDIT_WRITE      29

/**
 * 通过netlink套接字控制内核审计操作
 */
#define CAP_AUDIT_CONTROL    30

#ifdef __KERNEL__
/* 
 * Bounding set
 */
extern kernel_cap_t cap_bset;

/*
 * Internal kernel functions only
 */
 
#ifdef STRICT_CAP_T_TYPECHECKS

#define to_cap_t(x) { x }
#define cap_t(x) (x).cap

#else

#define to_cap_t(x) (x)
#define cap_t(x) (x)

#endif

#define CAP_EMPTY_SET       to_cap_t(0)
#define CAP_FULL_SET        to_cap_t(~0)
#define CAP_INIT_EFF_SET    to_cap_t(~0 & ~CAP_TO_MASK(CAP_SETPCAP))
#define CAP_INIT_INH_SET    to_cap_t(0)

#define CAP_TO_MASK(x) (1 << (x))
#define cap_raise(c, flag)   (cap_t(c) |=  CAP_TO_MASK(flag))
#define cap_lower(c, flag)   (cap_t(c) &= ~CAP_TO_MASK(flag))
#define cap_raised(c, flag)  (cap_t(c) & CAP_TO_MASK(flag))

static inline kernel_cap_t cap_combine(kernel_cap_t a, kernel_cap_t b)
{
     kernel_cap_t dest;
     cap_t(dest) = cap_t(a) | cap_t(b);
     return dest;
}

static inline kernel_cap_t cap_intersect(kernel_cap_t a, kernel_cap_t b)
{
     kernel_cap_t dest;
     cap_t(dest) = cap_t(a) & cap_t(b);
     return dest;
}

static inline kernel_cap_t cap_drop(kernel_cap_t a, kernel_cap_t drop)
{
     kernel_cap_t dest;
     cap_t(dest) = cap_t(a) & ~cap_t(drop);
     return dest;
}

static inline kernel_cap_t cap_invert(kernel_cap_t c)
{
     kernel_cap_t dest;
     cap_t(dest) = ~cap_t(c);
     return dest;
}

#define cap_isclear(c)       (!cap_t(c))
#define cap_issubset(a,set)  (!(cap_t(a) & ~cap_t(set)))

#define cap_clear(c)         do { cap_t(c) =  0; } while(0)
#define cap_set_full(c)      do { cap_t(c) = ~0; } while(0)
#define cap_mask(c,mask)     do { cap_t(c) &= cap_t(mask); } while(0)

#define cap_is_fs_cap(c)     (CAP_TO_MASK(c) & CAP_FS_MASK)

#endif /* __KERNEL__ */

#endif /* !_LINUX_CAPABILITY_H */
