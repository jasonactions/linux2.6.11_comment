#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/minix_fs.h>

/*
 * change the define below to 0 if you want names > info->s_namelen chars to be
 * truncated. Else they will be disallowed (ENAMETOOLONG).
 */
#define NO_TRUNCATE 1

#define INODE_VERSION(inode)	minix_sb(inode->i_sb)->s_version

#define MINIX_V1		0x0001		/* original minix fs */
#define MINIX_V2		0x0002		/* minix V2 fs */

/*
 * minix fs inode data in memory
 */
/* 内存中的MINIX节点 */
struct minix_inode_info {
	union {
		/* 文件所占用的盘上逻辑块号数组，针对2.0版本 */
		__u16 i1_data[16];
		/* 文件所占用的盘上逻辑块号数组，其中0-6是直接块号，7是一次间接块，8是二次间接块，9是三次间接块 */
		__u32 i2_data[16];
	} u;
	/* 内嵌的VFS节点 */
	struct inode vfs_inode;
};

/*
 * minix super-block data in memory
 */
/* MINIX文件系统在内存中的超级块结构 */
struct minix_sb_info {
	/* i节点数 */
	unsigned long s_ninodes;
	/* 逻辑块数 */
	unsigned long s_nzones;
	/* i节点位图所占块数 */
	unsigned long s_imap_blocks;
	/* 逻辑块位图所占块数 */
	unsigned long s_zmap_blocks;
	/* 数据区中第一个逻辑块号 */
	unsigned long s_firstdatazone;
	/* log2(磁盘块数/逻辑块) */
	unsigned long s_log_zone_size;
	/* 最大的文件长度，以字节为单位 */
	unsigned long s_max_size;
	/* 目录项的长度 */
	int s_dirsize;
	/* 目录项中文件名的长度 */
	int s_namelen;
	/* 最大的链接数 */
	int s_link_max;
	/* i节点位图缓冲区 */
	struct buffer_head ** s_imap;
	/* 逻辑块位图缓冲区 */
	struct buffer_head ** s_zmap;
	/* 超级块缓冲区 */
	struct buffer_head * s_sbh;
	/* 指向磁盘上超级块的指针 */
	struct minix_super_block * s_ms;
	unsigned short s_mount_state;
	/* 文件系统版本 */
	unsigned short s_version;
};

extern struct minix_inode * minix_V1_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct minix2_inode * minix_V2_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct inode * minix_new_inode(const struct inode * dir, int * error);
extern void minix_free_inode(struct inode * inode);
extern unsigned long minix_count_free_inodes(struct minix_sb_info *sbi);
extern int minix_new_block(struct inode * inode);
extern void minix_free_block(struct inode * inode, int block);
extern unsigned long minix_count_free_blocks(struct minix_sb_info *sbi);

extern int minix_getattr(struct vfsmount *, struct dentry *, struct kstat *);

extern void V2_minix_truncate(struct inode *);
extern void V1_minix_truncate(struct inode *);
extern void V2_minix_truncate(struct inode *);
extern void minix_truncate(struct inode *);
extern int minix_sync_inode(struct inode *);
extern void minix_set_inode(struct inode *, dev_t);
extern int V1_minix_get_block(struct inode *, long, struct buffer_head *, int);
extern int V2_minix_get_block(struct inode *, long, struct buffer_head *, int);
extern unsigned V1_minix_blocks(loff_t);
extern unsigned V2_minix_blocks(loff_t);

extern struct minix_dir_entry *minix_find_entry(struct dentry*, struct page**);
extern int minix_add_link(struct dentry*, struct inode*);
extern int minix_delete_entry(struct minix_dir_entry*, struct page*);
extern int minix_make_empty(struct inode*, struct inode*);
extern int minix_empty_dir(struct inode*);
extern void minix_set_link(struct minix_dir_entry*, struct page*, struct inode*);
extern struct minix_dir_entry *minix_dotdot(struct inode*, struct page**);
extern ino_t minix_inode_by_name(struct dentry*);

extern int minix_sync_file(struct file *, struct dentry *, int);

extern struct inode_operations minix_file_inode_operations;
extern struct inode_operations minix_dir_inode_operations;
extern struct file_operations minix_file_operations;
extern struct file_operations minix_dir_operations;
extern struct dentry_operations minix_dentry_operations;

static inline struct minix_sb_info *minix_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct minix_inode_info *minix_i(struct inode *inode)
{
	return list_entry(inode, struct minix_inode_info, vfs_inode);
}
