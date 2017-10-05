/*
 * linux/fs/recovery.c
 * 
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999-2000 Red Hat Software --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal recovery routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.  
 */

#ifndef __KERNEL__
#include "jfs_user.h"
#else
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#endif

/*
 * Maintain information about the progress of the recovery job, so that
 * the different passes can carry information between them. 
 */
/**
 * 恢复日志所用信息
 */
struct recovery_info 
{
	/* 起止事务号 */
	tid_t		start_transaction;
	tid_t		end_transaction;

	/* so obvious */
	int		nr_replays;
	int		nr_revokes;
	int		nr_revoke_hits;
};

/**
 * PASS_SCAN:
 *	查找到日志末端。
 * PASS_REVOKE:
 *	查找日志中所有撤销块。
 * PASS_REPLAY:
 *	将所有未被撤销的块写入到磁盘，以确保一致性。
 */
enum passtype {PASS_SCAN, PASS_REVOKE, PASS_REPLAY};
static int do_one_pass(journal_t *journal,
				struct recovery_info *info, enum passtype pass);
static int scan_revoke_records(journal_t *, struct buffer_head *,
				tid_t, struct recovery_info *);

#ifdef __KERNEL__

/* Release readahead buffers after use */
void journal_brelse_array(struct buffer_head *b[], int n)
{
	while (--n >= 0)
		brelse (b[n]);
}


/*
 * When reading from the journal, we are going through the block device
 * layer directly and so there is no readahead being done for us.  We
 * need to implement any readahead ourselves if we want it to happen at
 * all.  Recovery is basically one long sequential read, so make sure we
 * do the IO in reasonably large chunks.
 *
 * This is not so critical that we need to be enormously clever about
 * the readahead size, though.  128K is a purely arbitrary, good-enough
 * fixed value.
 */

#define MAXBUF 8
static int do_readahead(journal_t *journal, unsigned int start)
{
	int err;
	unsigned int max, nbufs, next;
	unsigned long blocknr;
	struct buffer_head *bh;

	struct buffer_head * bufs[MAXBUF];

	/* Do up to 128K of readahead */
	max = start + (128 * 1024 / journal->j_blocksize);
	if (max > journal->j_maxlen)
		max = journal->j_maxlen;

	/* Do the readahead itself.  We'll submit MAXBUF buffer_heads at
	 * a time to the block device IO layer. */

	nbufs = 0;

	for (next = start; next < max; next++) {
		err = journal_bmap(journal, next, &blocknr);

		if (err) {
			printk (KERN_ERR "JBD: bad block at offset %u\n",
				next);
			goto failed;
		}

		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		if (!bh) {
			err = -ENOMEM;
			goto failed;
		}

		if (!buffer_uptodate(bh) && !buffer_locked(bh)) {
			bufs[nbufs++] = bh;
			if (nbufs == MAXBUF) {
				ll_rw_block(READ, nbufs, bufs);
				journal_brelse_array(bufs, nbufs);
				nbufs = 0;
			}
		} else
			brelse(bh);
	}

	if (nbufs)
		ll_rw_block(READ, nbufs, bufs);
	err = 0;

failed:
	if (nbufs) 
		journal_brelse_array(bufs, nbufs);
	return err;
}

#endif /* __KERNEL__ */


/*
 * Read a block from the journal
 */

static int jread(struct buffer_head **bhp, journal_t *journal, 
		 unsigned int offset)
{
	int err;
	unsigned long blocknr;
	struct buffer_head *bh;

	*bhp = NULL;

	if (offset >= journal->j_maxlen) {
		printk(KERN_ERR "JBD: corrupted journal superblock\n");
		return -EIO;
	}

	err = journal_bmap(journal, offset, &blocknr);

	if (err) {
		printk (KERN_ERR "JBD: bad block at offset %u\n",
			offset);
		return err;
	}

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh)
		return -ENOMEM;

	if (!buffer_uptodate(bh)) {
		/* If this is a brand new buffer, start readahead.
                   Otherwise, we assume we are already reading it.  */
		if (!buffer_req(bh))
			do_readahead(journal, offset);
		wait_on_buffer(bh);
	}

	if (!buffer_uptodate(bh)) {
		printk (KERN_ERR "JBD: Failed to read block at offset %u\n",
			offset);
		brelse(bh);
		return -EIO;
	}

	*bhp = bh;
	return 0;
}


/*
 * Count the number of in-use tags in a journal descriptor block.
 */

static int count_tags(struct buffer_head *bh, int size)
{
	char *			tagp;
	journal_block_tag_t *	tag;
	int			nr = 0;

	tagp = &bh->b_data[sizeof(journal_header_t)];

	while ((tagp - bh->b_data + sizeof(journal_block_tag_t)) <= size) {
		tag = (journal_block_tag_t *) tagp;

		nr++;
		tagp += sizeof(journal_block_tag_t);
		if (!(tag->t_flags & cpu_to_be32(JFS_FLAG_SAME_UUID)))
			tagp += 16;

		if (tag->t_flags & cpu_to_be32(JFS_FLAG_LAST_TAG))
			break;
	}

	return nr;
}


/* Make sure we wrap around the log correctly! */
#define wrap(journal, var)						\
do {									\
	if (var >= (journal)->j_last)					\
		var -= ((journal)->j_last - (journal)->j_first);	\
} while (0)

/**
 * int journal_recover(journal_t *journal) - recovers a on-disk journal
 * @journal: the journal to recover
 * 
 * The primary function for recovering the log contents when mounting a
 * journaled device.  
 *
 * Recovery is done in three passes.  In the first pass, we look for the
 * end of the log.  In the second, we assemble the list of revoke
 * blocks.  In the third and final pass, we replay any un-revoked blocks
 * in the log.  
 */
/**
 * 日志恢复主函数
 */
int journal_recover(journal_t *journal)
{
	int			err;
	journal_superblock_t *	sb;

	struct recovery_info	info;

	memset(&info, 0, sizeof(info));
	sb = journal->j_superblock;

	/* 
	 * The journal superblock's s_start field (the current log head)
	 * is always zero if, and only if, the journal was cleanly
	 * unmounted.  
	 */

	/* 文件系统被正常卸载 */
	if (!sb->s_start) {
		jbd_debug(1, "No recovery required, last transaction %d\n",
			  be32_to_cpu(sb->s_sequence));
		/**
		 * 递增日志序号，退出
		 */
		journal->j_transaction_sequence = be32_to_cpu(sb->s_sequence) + 1;
		return 0;
	}

	/* 找到日志的终点和起点 */
	err = do_one_pass(journal, &info, PASS_SCAN);
	if (!err)
		/* 找到撤销块，将其信息读到哈希表中 */
		err = do_one_pass(journal, &info, PASS_REVOKE);
	if (!err)
		/* 根据日志描述符的指示，将数据恢复到磁盘 */
		err = do_one_pass(journal, &info, PASS_REPLAY);

	jbd_debug(0, "JBD: recovery, exit status %d, "
		  "recovered transactions %u to %u\n",
		  err, info.start_transaction, info.end_transaction);
	jbd_debug(0, "JBD: Replayed %d and revoked %d/%d blocks\n", 
		  info.nr_replays, info.nr_revoke_hits, info.nr_revokes);

	/* Restart the log at the next transaction ID, thus invalidating
	 * any existing commit records in the log. */
	/**
	 * 递增日志序号，使其无效
	 */
	journal->j_transaction_sequence = ++info.end_transaction;

	/* 清空撤销表 */
	journal_clear_revoke(journal);
	/* 同步日志磁盘数据 */
	sync_blockdev(journal->j_fs_dev);
	return err;
}

/**
 * int journal_skip_recovery() - Start journal and wipe exiting records 
 * @journal: journal to startup
 * 
 * Locate any valid recovery information from the journal and set up the
 * journal structures in memory to ignore it (presumably because the
 * caller has evidence that it is out of date).  
 * This function does'nt appear to be exorted..
 *
 * We perform one pass over the journal to allow us to tell the user how
 * much recovery information is being erased, and to let us initialise
 * the journal transaction sequence numbers to the next unused ID. 
 */
int journal_skip_recovery(journal_t *journal)
{
	int			err;
	journal_superblock_t *	sb;

	struct recovery_info	info;

	memset (&info, 0, sizeof(info));
	sb = journal->j_superblock;

	err = do_one_pass(journal, &info, PASS_SCAN);

	if (err) {
		printk(KERN_ERR "JBD: error %d scanning journal\n", err);
		++journal->j_transaction_sequence;
	} else {
#ifdef CONFIG_JBD_DEBUG
		int dropped = info.end_transaction - be32_to_cpu(sb->s_sequence);
#endif
		jbd_debug(0, 
			  "JBD: ignoring %d transaction%s from the journal.\n",
			  dropped, (dropped == 1) ? "" : "s");
		journal->j_transaction_sequence = ++info.end_transaction;
	}

	journal->j_tail = 0;
	return err;
}

static int do_one_pass(journal_t *journal,
			struct recovery_info *info, enum passtype pass)
{
	unsigned int		first_commit_ID, next_commit_ID;
	unsigned long		next_log_block;
	int			err, success = 0;
	journal_superblock_t *	sb;
	journal_header_t * 	tmp;
	struct buffer_head *	bh;
	unsigned int		sequence;
	int			blocktype;

	/* Precompute the maximum metadata descriptors in a descriptor block */
	int			MAX_BLOCKS_PER_DESC;
	MAX_BLOCKS_PER_DESC = ((journal->j_blocksize-sizeof(journal_header_t))
			       / sizeof(journal_block_tag_t));

	/* 
	 * First thing is to establish what we expect to find in the log
	 * (in terms of transaction IDs), and where (in terms of log
	 * block offsets): query the superblock.  
	 */

	sb = journal->j_superblock;
	/* 下一个事务号 */
	next_commit_ID = be32_to_cpu(sb->s_sequence);
	/* 下一个要读取的日志块号 */
	next_log_block = be32_to_cpu(sb->s_start);

	first_commit_ID = next_commit_ID;
	if (pass == PASS_SCAN)
		info->start_transaction = first_commit_ID;

	jbd_debug(1, "Starting recovery pass %d\n", pass);

	/*
	 * Now we walk through the log, transaction by transaction,
	 * making sure that each transaction has a commit block in the
	 * expected place.  Each complete transaction gets replayed back
	 * into the main filesystem. 
	 */

	/**
	 * 遍历所有块
	 */
	while (1) {
		int			flags;
		char *			tagp;
		journal_block_tag_t *	tag;
		struct buffer_head *	obh;
		struct buffer_head *	nbh;

		cond_resched();		/* We're under lock_kernel() */

		/* If we already know where to stop the log traversal,
		 * check right now that we haven't gone past the end of
		 * the log. */

		if (pass != PASS_SCAN)
			if (tid_geq(next_commit_ID, info->end_transaction))
				break;

		jbd_debug(2, "Scanning for sequence ID %u at %lu/%lu\n",
			  next_commit_ID, next_log_block, journal->j_last);

		/* Skip over each chunk of the transaction looking
		 * either the next descriptor block or the final commit
		 * record. */

		jbd_debug(3, "JBD: checking block %ld\n", next_log_block);
		/* 读当前块 */
		err = jread(&bh, journal, next_log_block);
		if (err)
			goto failed;

		next_log_block++;
		/* 环形缓冲区，回绕处理 */
		wrap(journal, next_log_block);

		/* What kind of buffer is it? 
		 * 
		 * If it is a descriptor block, check that it has the
		 * expected sequence number.  Otherwise, we're all done
		 * here. */

		tmp = (journal_header_t *)bh->b_data;

		/**
		 * 不是日志描述块
		 * 注意在提交日志时，元数据块是转义了的
		 */
		if (tmp->h_magic != cpu_to_be32(JFS_MAGIC_NUMBER)) {
			brelse(bh);
			break;
		}

		/* 描述块类型及事务序号 */
		blocktype = be32_to_cpu(tmp->h_blocktype);
		sequence = be32_to_cpu(tmp->h_sequence);
		jbd_debug(3, "Found magic %d, sequence %d\n", 
			  blocktype, sequence);

		/* 和预期序号不符，退 */
		if (sequence != next_commit_ID) {
			brelse(bh);
			break;
		}

		/* OK, we have a valid descriptor block which matches
		 * all of the sequence number checks.  What are we going
		 * to do with it?  That depends on the pass... */

		switch(blocktype) {
		/* 描述符块，后跟元数据 */
		case JFS_DESCRIPTOR_BLOCK:
			/* If it is a valid descriptor block, replay it
			 * in pass REPLAY; otherwise, just skip over the
			 * blocks it describes. */
			if (pass != PASS_REPLAY) {
				/* 计算数据块有多少 */
				next_log_block +=
					count_tags(bh, journal->j_blocksize);
				wrap(journal, next_log_block);
				brelse(bh);
				continue;
			}

			/* A descriptor block: we can now write all of
			 * the data blocks.  Yay, useful work is finally
			 * getting done here! */

			/**
			 * 这里开始执行replay操作
			 * 先读出日志块的头
			 */
			tagp = &bh->b_data[sizeof(journal_header_t)];
			while ((tagp - bh->b_data +sizeof(journal_block_tag_t))
			       <= journal->j_blocksize) {/* 遍历一个整块，找tag */
				unsigned long io_block;

				tag = (journal_block_tag_t *) tagp;
				flags = be32_to_cpu(tag->t_flags);

				/* 下一个元数据块 */
				io_block = next_log_block++;
				wrap(journal, next_log_block);
				/* 将元数据读到内存中 */
				err = jread(&obh, journal, io_block);
				if (err) {/* :( */
					/* Recover what we can, but
					 * report failure at the end. */
					success = err;
					printk (KERN_ERR 
						"JBD: IO error %d recovering "
						"block %ld in log\n",
						err, io_block);
				} else {
					unsigned long blocknr;

					J_ASSERT(obh != NULL);
					/* 目标文件的块号 */
					blocknr = be32_to_cpu(tag->t_blocknr);

					/* If the block has been
					 * revoked, then we're all done
					 * here. */
					/* 位于撤销块，省点事情，略过 */
					if (journal_test_revoke
					    (journal, blocknr, 
					     next_commit_ID)) {
						brelse(obh);
						++info->nr_revoke_hits;
						goto skip_write;
					}

					/* Find a buffer for the new
					 * data being restored */
					/**
					 * 读取目标文件系统的数据
					 * 要被覆盖的，但是也需要读
					 * 这样才能在块设备层中形成缓存
					 */
					nbh = __getblk(journal->j_fs_dev,
							blocknr,
							journal->j_blocksize);
					if (nbh == NULL) {/* :( */
						printk(KERN_ERR 
						       "JBD: Out of memory "
						       "during recovery.\n");
						err = -ENOMEM;
						brelse(bh);
						brelse(obh);
						goto failed;
					}

					/* 锁定目标块 */
					lock_buffer(nbh);
					/* 从日志中复制数据过去 */
					memcpy(nbh->b_data, obh->b_data,
							journal->j_blocksize);
					/* 转义了 */
					if (flags & JFS_FLAG_ESCAPE) {
						/* 恢复被转义的字节 */
						*((__be32 *)bh->b_data) =
						cpu_to_be32(JFS_MAGIC_NUMBER);
					}

					/* balabala，扫尾 */
					BUFFER_TRACE(nbh, "marking dirty");
					/**
					 * 这里仅仅是标记脏
					 */
					set_buffer_uptodate(nbh);
					mark_buffer_dirty(nbh);
					BUFFER_TRACE(nbh, "marking uptodate");
					++info->nr_replays;
					/**
					 * 这里也没有提交块，代码被注释掉了
					 * 能嗅出一点什么不对的地方吗?
					 */
					/* ll_rw_block(WRITE, 1, &nbh); */
					unlock_buffer(nbh);
					brelse(obh);
					brelse(nbh);
				}

			skip_write:
				tagp += sizeof(journal_block_tag_t);
				if (!(flags & JFS_FLAG_SAME_UUID))
					tagp += 16;

				if (flags & JFS_FLAG_LAST_TAG)
					break;
			}

			brelse(bh);
			continue;

		/* 提交块，应当开启下一个事务 */
		case JFS_COMMIT_BLOCK:
			/* Found an expected commit block: not much to
			 * do other than move on to the next sequence
			 * number. */
			brelse(bh);
			next_commit_ID++;
			continue;

		/* 撤销块 */
		case JFS_REVOKE_BLOCK:
			/* If we aren't in the REVOKE pass, then we can
			 * just skip over this block. */
			if (pass != PASS_REVOKE) {/* 仅仅在第二步才有用 */
				brelse(bh);
				continue;
			}

			/**
			 * 第二步
			 * 将撤销块记录到内存中
			 */
			err = scan_revoke_records(journal, bh,
						  next_commit_ID, info);
			brelse(bh);
			if (err)
				goto failed;
			continue;

		/* 撞上鬼了 */
		default:
			jbd_debug(3, "Unrecognised magic %d, end of scan.\n",
				  blocktype);
			goto done;
		}
	}

 done:
	/* 
	 * We broke out of the log scan loop: either we came to the
	 * known end of the log or we found an unexpected block in the
	 * log.  If the latter happened, then we know that the "current"
	 * transaction marks the end of the valid log.
	 */

	/* 第一遍遍历 */
	if (pass == PASS_SCAN)
		info->end_transaction = next_commit_ID;/* 记录下起止事务号即可 */
	else {
		/* It's really bad news if different passes end up at
		 * different places (but possible due to IO errors). */
		if (info->end_transaction != next_commit_ID) {
			printk (KERN_ERR "JBD: recovery pass %d ended at "
				"transaction %u, expected %u\n",
				pass, next_commit_ID, info->end_transaction);
			if (!success)
				success = -EIO;
		}
	}

	return success;

 failed:
	return err;
}


/* Scan a revoke record, marking all blocks mentioned as revoked. */

static int scan_revoke_records(journal_t *journal, struct buffer_head *bh, 
			       tid_t sequence, struct recovery_info *info)
{
	journal_revoke_header_t *header;
	int offset, max;

	header = (journal_revoke_header_t *) bh->b_data;
	offset = sizeof(journal_revoke_header_t);
	/* 撤销块占用的字节数 */
	max = be32_to_cpu(header->r_count);

	while (offset < max) {/* 遍历磁盘上所有字节 */
		unsigned long blocknr;
		int err;

		/* 被撤销的块号 */
		blocknr = be32_to_cpu(* ((__be32 *) (bh->b_data+offset)));
		offset += 4;
		/* 记录到内存中 */
		err = journal_set_revoke(journal, blocknr, sequence);
		if (err)
			return err;
		/* 撤销块计数 */
		++info->nr_revokes;
	}
	return 0;
}
