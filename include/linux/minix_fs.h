#ifndef _LINUX_MINIX_FS_H
#define _LINUX_MINIX_FS_H

/*
 * The minix filesystem constants/structures
 */

/*
 * Thanks to Kees J Bot for sending me the definitions of the new
 * minix filesystem (aka V2) with bigger inodes and 32-bit block
 * pointers.
 */

#define MINIX_ROOT_INO 1

/* Not the same as the bogus LINK_MAX in <linux/limits.h>. Oh well. */
#define MINIX_LINK_MAX	250
#define MINIX2_LINK_MAX	65530

#define MINIX_I_MAP_SLOTS	8
#define MINIX_Z_MAP_SLOTS	64
#define MINIX_SUPER_MAGIC	0x137F		/* original minix fs */
#define MINIX_SUPER_MAGIC2	0x138F		/* minix fs, 30 char names */
#define MINIX2_SUPER_MAGIC	0x2468		/* minix V2 fs */
#define MINIX2_SUPER_MAGIC2	0x2478		/* minix V2 fs, 30 char names */
#define MINIX_VALID_FS		0x0001		/* Clean fs. */
#define MINIX_ERROR_FS		0x0002		/* fs has errors. */

#define MINIX_INODES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct minix_inode)))
#define MINIX2_INODES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct minix2_inode)))

/*
 * This is the original minix inode layout on disk.
 * Note the 8-bit gid and atime and ctime.
 */
struct minix_inode {
	__u16 i_mode;
	__u16 i_uid;
	__u32 i_size;
	__u32 i_time;
	__u8  i_gid;
	__u8  i_nlinks;
	__u16 i_zone[9];
};

/*
 * The new minix inode has all the time entries, as well as
 * long block numbers and a third indirect block (7+1+1+1
 * instead of 7+1+1). Also, some previously 8-bit values are
 * now 16-bit. The inode is now 64 bytes instead of 32.
 */
/* MINIX3.0磁盘上的节点结构 */
struct minix2_inode {
	/* 文件系统的类型和模式 */
	__u16 i_mode;
	/* 链接数 */
	__u16 i_nlinks;
	/* owner id */
	__u16 i_uid;
	/* groud id */
	__u16 i_gid;
	/* 文件长度，以字节为单位 */
	__u32 i_size;
	/* 访问时间 */
	__u32 i_atime;
	/* 修改时间 */
	__u32 i_mtime;
	/* 创建时间 */
	__u32 i_ctime;
	/* 文件所占用的盘上逻辑块号数组，含直接块号，一次间接块号，二次间接块号，三次间接块号 */
	__u32 i_zone[10];
};

/*
 * minix super-block data on disk
 */
/* MINIX磁盘上超级块描述符 */
struct minix_super_block {
	/* i节点数 */
	__u16 s_ninodes;
	/* 逻辑块数 */
	__u16 s_nzones;
	/* i节点位图所占块数 */
	__u16 s_imap_blocks;
	/* 逻辑块位图所占块数 */
	__u16 s_zmap_blocks;
	/* 数据区中第一个逻辑块号 */
	__u16 s_firstdatazone;
	/* log2(磁盘块数/逻辑块) */
	__u16 s_log_zone_size;
	/* 最大文件长度 */
	__u32 s_max_size;
	/* 文件系统魔数 */
	__u16 s_magic;
	__u16 s_state;
	__u32 s_zones;
};

/* 磁盘上的目录项结构 */
struct minix_dir_entry {
	/* i节点编号 */
	__u16 inode;
	/* 名称 */
	char name[0];
};

#endif
