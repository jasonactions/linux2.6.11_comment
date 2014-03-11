/*
 * NFS protocol definitions
 *
 * This file contains constants for Version 2 of the protocol.
 */
#ifndef _LINUX_NFS2_H
#define _LINUX_NFS2_H

#define NFS2_PORT	2049
#define NFS2_MAXDATA	8192
#define NFS2_MAXPATHLEN	1024
#define NFS2_MAXNAMLEN	255
#define NFS2_MAXGROUPS	16
#define NFS2_FHSIZE	32
#define NFS2_COOKIESIZE	4
#define NFS2_FIFO_DEV	(-1)
#define NFS2MODE_FMT	0170000
#define NFS2MODE_DIR	0040000
#define NFS2MODE_CHR	0020000
#define NFS2MODE_BLK	0060000
#define NFS2MODE_REG	0100000
#define NFS2MODE_LNK	0120000
#define NFS2MODE_SOCK	0140000
#define NFS2MODE_FIFO	0010000


/* NFSv2 file types - beware, these are not the same in NFSv3 */
enum nfs2_ftype {
	NF2NON = 0,
	NF2REG = 1,
	NF2DIR = 2,
	NF2BLK = 3,
	NF2CHR = 4,
	NF2LNK = 5,
	NF2SOCK = 6,
	NF2BAD = 7,
	NF2FIFO = 8
};

struct nfs2_fh {
	char			data[NFS2_FHSIZE];
};

/*
 * Procedure numbers for NFSv2
 */
/**
 * NFS程序号。
 */
#define NFS2_VERSION		2
/**
 * 按照习惯，在任何RPC程序中过程0被称为空，因为它没有任何动作。
 * 应用程序可以调用它来测试某个服务器是否响应。
 */
#define NFSPROC_NULL		0
/**
 * 客户机调用过程1来得到某个文件的属性，包括保护模式、文件拥有者、大小以及最近存取时间等项。
 */
#define NFSPROC_GETATTR		1
/**
 * 过程2允许客户机设置文件的某些属性。客户机不能设置所有属性（例如fsid、rdev、fileid等）。如果调用成功，将会返回改变后文件的属性。
 */
#define NFSPROC_SETATTR		2
/**
 * 此过程在NFS3中已经不存在，被安装协议取代。
 */
#define NFSPROC_ROOT		3
/**
 * 此过程在一个目录中搜索某个文件。如果成功，则返回的值由该文件的属性及其句柄组成。
 */
#define NFSPROC_LOOKUP		4
/**
 * 允许客户机把符号连接的值读出来。
 */
#define NFSPROC_READLINK	5
/**
 * 允许客户机从某个文件中读出数据。服务器如果操作成功，返回结果包含了所需要的数据及该文件的属性；如果操作失败，则状态值包含了一个差错代码。
 */
#define NFSPROC_READ		6
/**
 * 此过程在NFS3中已经不存在。
 */
#define NFSPROC_WRITECACHE	7
/**
 * 允许客户向一个远程文件写入数据。调用成功返回文件的属性，否则包含一个错误代码。
 */
#define NFSPROC_WRITE		8
/**
 * 客户机调用过程9在一个指定目录创建一个文件。该文件不能存在，否则该调用将返回差错。调用如果成功，将返回新文件的句柄及其属性。
 */
#define NFSPROC_CREATE		9
/**
 * 客户机调用过程10来删除一个已经存在的文件。该调用返回一个状态值。该状态值指示此操作是否成功。
 */
#define NFSPROC_REMOVE		10
/**
 * 客户机调用过程11为一个文件改名。由于参数使客户机可以指定文件的新的名字和新的目录，所以rename操作就对应着UNIXC的mv命令。NFS保证rename在服务器上是原子操作（也就是说，它的执行不会被中断）。对原子性的保证十分重要，因为它意味着知道安装好文件的新名才能把旧名删除。
 */
#define NFSPROC_RENAME		11
/**
 * 过程12允许客户机形成一个到已存在文件的硬连接。NFS保证，如果一个文件有多个连接，那么无论用哪条连接对该文件进行存取，文件的可视属性都是一致的。
 */
#define NFSPROC_LINK		12
/**
 * 过程13创建一个符号连接。参数指明了一个目录句柄、要创建的文件名以及作为该符号连接内容的字符串。
 */
#define NFSPROC_SYMLINK		13
/**
 * 过程14创建一个目录。如果调用成功，则服务器返回新目录的句柄及其属性。
 */
#define NFSPROC_MKDIR		14
/**
 * 客户机调用过程15来删除一个目录。正如在UNIX中一样，一个目录被删除以前必须是空的。
 */
#define NFSPROC_RMDIR		15
/**
 * 客户机调用过程16从一个目录中读取其中的目录项。
 */
#define NFSPROC_READDIR		16
/**
 * 过程17允许客户机得到驻留有某个文件的文件系统的信息。
 * 返回结果包括以下信息：指明最优传输大小（即在read或write请求中的数据长度，这个长度可以产生最优的传输率）、存储设备的数据块大小、设备的块数、当前未使用的块数以及非特权用户可用的未使用块数。
 */
#define NFSPROC_STATFS		17

#define NFS_MNT_PROGRAM		100005
#define NFS_MNT_VERSION		1
#define MNTPROC_NULL		0
#define MNTPROC_MNT		1
#define MNTPROC_UMNT		3
#define MNTPROC_UMNTALL		4

#endif /* _LINUX_NFS2_H */
