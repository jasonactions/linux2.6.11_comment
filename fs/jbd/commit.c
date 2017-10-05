/*
 * linux/fs/commit.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal commit routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

/*
 * Default IO end handler for temporary BJ_IO buffer_heads.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	unlock_buffer(bh);
}

/*
 * When an ext3-ordered file is truncated, it is possible that many pages are
 * not sucessfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under lock_journal(), and possibly under journal_datalist_lock.  The
 * caller provided us with a ref against the buffer, and we drop that here.
 */
static void release_buffer_page(struct buffer_head *bh)
{
	struct page *page;

	if (buffer_dirty(bh))
		goto nope;
	if (atomic_read(&bh->b_count) != 1)
		goto nope;
	page = bh->b_page;
	if (!page)
		goto nope;
	if (page->mapping)
		goto nope;

	/* OK, it's a truncated page */
	if (TestSetPageLocked(page))
		goto nope;

	page_cache_get(page);
	__brelse(bh);
	try_to_free_buffers(page);
	unlock_page(page);
	page_cache_release(page);
	return;

nope:
	__brelse(bh);
}

/*
 * Try to acquire jbd_lock_bh_state() against the buffer, when j_list_lock is
 * held.  For ranking reasons we must trylock.  If we lose, schedule away and
 * return 0.  j_list_lock is dropped in this case.
 */
static int inverted_lock(journal_t *journal, struct buffer_head *bh)
{
	if (!jbd_trylock_bh_state(bh)) {
		spin_unlock(&journal->j_list_lock);
		schedule();
		return 0;
	}
	return 1;
}

/*
 * journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
/**
 * 提交日志的主函数。
 */
void journal_commit_transaction(journal_t *journal)
{
	transaction_t *commit_transaction;
	struct journal_head *jh, *new_jh, *descriptor;
	struct buffer_head *wbuf[64];
	int bufs;
	int flags;
	int err;
	unsigned long blocknr;
	char *tagp = NULL;
	journal_header_t *header;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i;

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */

#ifdef COMMIT_STATS
	spin_lock(&journal->j_list_lock);
	summarise_journal_usage(journal);
	spin_unlock(&journal->j_list_lock);
#endif

	/* Do we need to erase the effects of a prior journal_flush? */
	if (journal->j_flags & JFS_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		journal_update_superblock(journal, 1);
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

	commit_transaction = journal->j_running_transaction;
	J_ASSERT(commit_transaction->t_state == T_RUNNING);

	/**
	 * 第一个阶段
	 * 将事务从运行状态转换为锁定状态。
	 * 这意味着事务不再接受新的原子操作。
	 * 因为日志线程可能是到期了，需要强制结束当前事务。
	 */
	jbd_debug(1, "JBD: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	spin_lock(&journal->j_state_lock);
	commit_transaction->t_state = T_LOCKED;

	spin_lock(&commit_transaction->t_handle_lock);
	/**
	 * 等待已经存在的原子操作完成。
	 */
	while (commit_transaction->t_updates) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (commit_transaction->t_updates) { /* 还有原子操作在其上运行 */
			spin_unlock(&commit_transaction->t_handle_lock);
			spin_unlock(&journal->j_state_lock);
			schedule();
			spin_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	J_ASSERT (commit_transaction->t_outstanding_credits <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple journal_get_write_access() calls to the same
	 * buffer are perfectly permissable.
	 */
	/**
	 * 在初始化事务时，有一些预留的缓存区。
	 * 这些缓冲区可能没有被使用，在此将其释放
	 */
	while (commit_transaction->t_reserved_list) {
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A journal_get_undo_access()+journal_release_buffer() may
		 * leave undo-committed data.
		 */
		/**
		 * journal_get_undo_access可能是复制一份位图缓冲区
		 * 这里将其释放
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			if (jh->b_committed_data) {
				kfree(jh->b_committed_data);
				jh->b_committed_data = NULL;
			}
			jbd_unlock_bh_state(bh);
		}
		/* 从链表中摘除，并进行一些释放操作 */
		journal_refile_buffer(journal, jh);
	}

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);
	/**
	 * 整理chckpoint链表，为提交日志做准备。
	 */
	__journal_clean_checkpoint_list(journal);
	spin_unlock(&journal->j_list_lock);

	jbd_debug (3, "JBD: commit phase 1\n");

	/*
	 * Switch to a new revoke table.
	 */
	journal_switch_revoke_table(journal);

	/**
	 * 将待提交的事务标记为T_FLUSH状态。
	 */
	commit_transaction->t_state = T_FLUSH;
	/**
	 * 将事务标记为当前提交的事务。
	 */
	journal->j_committing_transaction = commit_transaction;
	/**
	 * 标记当前没有正在运行的事务。
	 * 因此，新的原子操作需要启动新的事务。
	 */
	journal->j_running_transaction = NULL;
	commit_transaction->t_log_start = journal->j_head;
	/**
	 * 已经可以开始新事务了
	 * 唤醒等待的事务
	 */
	wake_up(&journal->j_wait_transaction_locked);
	spin_unlock(&journal->j_state_lock);

	/**
	 * 第二阶段，将缓存区写入到磁盘。
	 */
	jbd_debug (3, "JBD: commit phase 2\n");

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */

	err = 0;
	/*
	 * Whenever we unlock the journal and sleep, things can get added
	 * onto ->t_sync_datalist, so we have to keep looping back to
	 * write_out_data until we *know* that the list is empty.
	 */
	bufs = 0;
	/*
	 * Cleanup any flushed data buffers from the data list.  Even in
	 * abort mode, we want to flush this out as soon as possible.
	 */
write_out_data:
	cond_resched();
	spin_lock(&journal->j_list_lock);

	/**
	 * 首先将数据缓冲区写入到磁盘。
	 */
	while (commit_transaction->t_sync_datalist) {/* 遍历数据缓冲区链表 */
		struct buffer_head *bh;

		/* 摘除头节点 */
		jh = commit_transaction->t_sync_datalist;
		commit_transaction->t_sync_datalist = jh->b_tnext;
		bh = jh2bh(jh);
		/**
		 * 这里试图提交时
		 * 后台也在提交，冲突
		 */
		if (buffer_locked(bh)) {
			BUFFER_TRACE(bh, "locked");
			if (!inverted_lock(journal, bh))
				goto write_out_data;
			/**
			 * 从sync_data链表取出来，放到lock链表中
			 * 等待后面提交
			 */
			__journal_unfile_buffer(jh);
			__journal_file_buffer(jh, commit_transaction,
						BJ_Locked);
			jbd_unlock_bh_state(bh);
			if (lock_need_resched(&journal->j_list_lock)) {
				spin_unlock(&journal->j_list_lock);
				goto write_out_data;
			}
		} else {
			if (buffer_dirty(bh)) {/* 缓冲区真的为脏，写入 */
				BUFFER_TRACE(bh, "start journal writeout");
				get_bh(bh);
				wbuf[bufs++] = bh;
				/**
				 * 脏缓冲区较多，先提交到磁盘。
				 */
				if (bufs == ARRAY_SIZE(wbuf)) {
					jbd_debug(2, "submit %d writes\n",
							bufs);
					spin_unlock(&journal->j_list_lock);
					/**
					 * 将缓冲区直接提交到磁盘中，注意不是日志中。
					 * 这里仅仅是发出IO请求
					 */
					ll_rw_block(WRITE, bufs, wbuf);
					/* against get_bh */
					journal_brelse_array(wbuf, bufs);
					bufs = 0;
					goto write_out_data;
				}
			} else {/* 没有脏，不用写入 */
				BUFFER_TRACE(bh, "writeout complete: unfile");
				if (!inverted_lock(journal, bh))
					/**
					 * 这里不应当跳回去
					 * 会造成内存泄漏
					 * 因为此时节点已经从链表中摘除了
					 */
					goto write_out_data;
				/**
				 * 做资源清理工作
				 */
				__journal_unfile_buffer(jh);
				jbd_unlock_bh_state(bh);
				journal_remove_journal_head(bh);
				put_bh(bh);
				/**
				 * 避免长期占用CPU
				 * 调度点
				 */
				if (lock_need_resched(&journal->j_list_lock)) {
					spin_unlock(&journal->j_list_lock);
					goto write_out_data;
				}
			}
		}
	}

	/**
	 * 将剩余的缓冲区写入到磁盘中。
	 */
	if (bufs) {
		spin_unlock(&journal->j_list_lock);
		ll_rw_block(WRITE, bufs, wbuf);
		journal_brelse_array(wbuf, bufs);
		spin_lock(&journal->j_list_lock);
	}

	/*
	 * Wait for all previously submitted IO to complete.
	 */
	/**
	 * 有一些数据块，已经被系统提交了，并处于锁定状态
	 * 这里等待其完成
	 */
	while (commit_transaction->t_locked_list) {/* 未在日志系统中提交的请求 */
		struct buffer_head *bh;

		jh = commit_transaction->t_locked_list->b_tprev;
		bh = jh2bh(jh);
		get_bh(bh);
		if (buffer_locked(bh)) {/* 被其他人锁住 */
			spin_unlock(&journal->j_list_lock);
			/* 等待解锁 */
			wait_on_buffer(bh);
			if (unlikely(!buffer_uptodate(bh)))
				err = -EIO;
			spin_lock(&journal->j_list_lock);
		}
		/* 临时开一下锁，避免长时间关抢占 */
		if (!inverted_lock(journal, bh)) {
			put_bh(bh);
			spin_lock(&journal->j_list_lock);
			continue;
		}
		/* 在开锁期间，没有谁将它从Locked链表中摘除 */
		if (buffer_jbd(bh) && jh->b_jlist == BJ_Locked) {
			/* 从链表中摘除 */
			__journal_unfile_buffer(jh);
			jbd_unlock_bh_state(bh);
			/* 释放描述符 */
			journal_remove_journal_head(bh);
			/*against  journal_remove_journal_head */
			put_bh(bh);
		} else {
			jbd_unlock_bh_state(bh);
		}
		put_bh(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (err)
		__journal_abort_hard(journal);

	/**
	 * 构建撤销表
	 * 会将撤销记录写到LogCtl链表中
	 */
	journal_write_revoke_records(journal, commit_transaction);

	/**
	 * 元数据仍然在内存中，开始处理元数据。
	 */
	jbd_debug(3, "JBD: commit phase 2\n");

	/*
	 * If we found any dirty or locked buffers, then we should have
	 * looped back up to the write_out_data label.  If there weren't
	 * any then journal_clean_data_list should have wiped the list
	 * clean by now, so check that it is in fact empty.
	 */
	J_ASSERT (commit_transaction->t_sync_datalist == NULL);

	jbd_debug (3, "JBD: commit phase 3\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	/**
	 * 标记正在写入元数据到日志中。
	 */
	commit_transaction->t_state = T_COMMIT;

	descriptor = NULL;
	bufs = 0;
	/* 遍历元数据链表 */
	while (commit_transaction->t_buffers) {

		/* Find the next buffer to be journaled... */

		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it for background writing. */

		/**
		 * 特殊情况，中止日志恢复，忽略事务。
		 */
		if (is_journal_aborted(journal)) {
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			journal_refile_buffer(journal, jh);
			/* If that was the last one, we need to clean up
			 * any descriptor buffers which may have been
			 * already allocated, even if we are now
			 * aborting. */
			if (!commit_transaction->t_buffers)
				goto start_journal_io;
			continue;
		}

		/* Make sure we have a descriptor block in which to
		   record the metadata buffer. */

		/**
		 * 目前还没有日志描述符块。
		 */
		if (!descriptor) {
			struct buffer_head *bh;

			J_ASSERT (bufs == 0);

			jbd_debug(4, "JBD: get descriptor\n");

			/* 分配一个 */
			descriptor = journal_get_descriptor_buffer(journal);
			if (!descriptor) {/* 内存不足，只好中止 */
				__journal_abort_hard(journal);
				continue;
			}

			/* bh是描述符在日志中的缓冲区 */
			bh = jh2bh(descriptor);
			jbd_debug(4, "JBD: got buffer %llu (%p)\n",
				(unsigned long long)bh->b_blocknr, bh->b_data);
			header = (journal_header_t *)&bh->b_data[0];
			header->h_magic     = cpu_to_be32(JFS_MAGIC_NUMBER);
			header->h_blocktype = cpu_to_be32(JFS_DESCRIPTOR_BLOCK);
			header->h_sequence  = cpu_to_be32(commit_transaction->t_tid);

			tagp = &bh->b_data[sizeof(journal_header_t)];
			space_left = bh->b_size - sizeof(journal_header_t);
			first_tag = 1;
			set_buffer_jwrite(bh);
			set_buffer_dirty(bh);
			/**
			 * 注意
			 * 这里将描述符块加到wbuf中
			 * 这样描述符块位于元数据块之前
			 */
			wbuf[bufs++] = bh;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(bh, "ph3: file as descriptor");
			/**
			 * 前面将撤销块写到LogCtl链表
			 * 这里将元数据控制块写入
			 */
			journal_file_buffer(descriptor, commit_transaction,
					BJ_LogCtl);
		}

		/* Where is the buffer to be written? */

		/**
		 * 计算元数据块应当放到哪一个日志块中。
		 */
		err = journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			__journal_abort_hard(journal);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by journal_next_log_block() also.
		 */
		/* 递减可用日志块数量，避免空间不足 */
		commit_transaction->t_outstanding_credits--;

		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the BJ_IO/BJ_Shadow pairing of buffers. */
		atomic_inc(&jh2bh(jh)->b_count);

		/* Make a temporary IO buffer with which to write it out
                   (this will requeue both the metadata buffer and the
                   temporary IO buffer). new_bh goes on BJ_IO*/

		set_bit(BH_JWrite, &jh2bh(jh)->b_state);
		/*
		 * akpm: journal_write_metadata_buffer() sets
		 * new_bh->b_transaction to commit_transaction.
		 * We need to clean this up before we release new_bh
		 * (which is of type BJ_IO)
		 */
		JBUFFER_TRACE(jh, "ph3: write metadata");
		/**
		 * 准备元数据到日志缓冲区中。
		 * 转义前的放在Shadow中，要写入的放在IO链表中
		 */
		flags = journal_write_metadata_buffer(commit_transaction,
						      jh, &new_jh, blocknr);
		set_bit(BH_JWrite, &jh2bh(new_jh)->b_state);
		wbuf[bufs++] = jh2bh(new_jh);

		/* Record the new block's tag in the current descriptor
                   buffer */

		tag_flag = 0;
		if (flags & 1)
			tag_flag |= JFS_FLAG_ESCAPE;
		if (!first_tag)
			tag_flag |= JFS_FLAG_SAME_UUID;

		/**
		 * 构建描述符块
		 */
		tag = (journal_block_tag_t *) tagp;
		tag->t_blocknr = cpu_to_be32(jh2bh(jh)->b_blocknr);
		tag->t_flags = cpu_to_be32(tag_flag);
		tagp += sizeof(journal_block_tag_t);
		space_left -= sizeof(journal_block_tag_t);

		if (first_tag) {
			memcpy (tagp, journal->j_uuid, 16);
			tagp += 16;
			space_left -= 16;
			first_tag = 0;
		}

		/* If there's no more to do, or if the descriptor is full,
		   let the IO rip! */

		/**
		 * 缓冲区数量过多，先提交一次。
		 */
		if (bufs == ARRAY_SIZE(wbuf) || /* 描述符块中包含的块过多，提交 */
		    commit_transaction->t_buffers == NULL || /* 所有元数据块都已经处理完 */
		    space_left < sizeof(journal_block_tag_t) + 16) { /* 剩余描述符空间已经不足处理一个完整的描述符 */

			jbd_debug(4, "JBD: Submit %d IOs\n", bufs);

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */

			tag->t_flags |= cpu_to_be32(JFS_FLAG_LAST_TAG);

start_journal_io:
			/**
			 * 在日志中提交描述符块和元数据块
			 */
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
				submit_bh(WRITE, bh);
			}
			cond_resched();

			/* Force a new descriptor to be generated next
                           time round the loop. */
                     /**
                      * 开始新一轮的工作，新建描述符
                      */
			descriptor = NULL;
			bufs = 0;
		}
	}

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the t_iobuf_list queue.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/

	jbd_debug(3, "JBD: commit phase 4\n");

	/*
	 * akpm: these are BJ_IO, and j_list_lock is not needed.
	 * See __journal_try_to_free_buffer.
	 */
wait_for_iobuf:
	/**
	 * 那些需要等待其完成完成的IO。
	 * 例如元数据及其控制头
	 */
	while (commit_transaction->t_iobuf_list != NULL) {
		struct buffer_head *bh;

		/* 取尾节点，我猜想这样可以少消耗一点CPU */
		jh = commit_transaction->t_iobuf_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {/* 还没有完成 */
			wait_on_buffer(bh);/* 等待解锁，完成IO */
			goto wait_for_iobuf;
		}
		if (cond_resched())
			goto wait_for_iobuf;

		/**
		 * 运行到这里，说明写入操作完成
		 * 写入失败了，严重的IO错误
		 */
		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		clear_buffer_jwrite(bh);

		JBUFFER_TRACE(jh, "ph4: unfile after journal write");
		/* 从IO链表中摘除 */
		journal_unfile_buffer(journal, jh);

		/*
		 * ->t_iobuf_list should contain only dummy buffer_heads
		 * which were created by journal_write_metadata_buffer().
		 */
		BUFFER_TRACE(bh, "dumping temporary bh");
		/* 释放内存 */
		journal_put_journal_head(jh);
		__brelse(bh);
		J_ASSERT_BH(bh, atomic_read(&bh->b_count) == 0);
		free_buffer_head(bh);

		/* We also have to unlock and free the corresponding
                   shadowed buffer */
              /**
               * Shadow链表中，是对应的原始缓冲区
               */
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);
		clear_bit(BH_JWrite, &bh->b_state);
		J_ASSERT_BH(bh, buffer_jbddirty(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
		/**
		 * 将其放到Forget链表中
		 * 用于checkpoint处理
		 */
		journal_file_buffer(jh, commit_transaction, BJ_Forget);
		/* Wake up any transactions which were waiting for this
		   IO to complete */
		 /**
		  * 现在，我们已经用完了块缓冲区
		  * 可以唤醒等待写这个缓冲区的线程了
		  * 那个线程正在调用do_get_write_access以获得写权限
		  */
		wake_up_bit(&bh->b_state, BH_Unshadow);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
		__brelse(bh);
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);

	jbd_debug(3, "JBD: commit phase 5\n");

	/* Here we wait for the revoke record and descriptor record buffers */
 wait_for_ctlbuf:
 	/**
	 * 等待控制块写入完毕。
	 * 以及撤销块
	 */
	while (commit_transaction->t_log_list != NULL) {
		struct buffer_head *bh;

		jh = commit_transaction->t_log_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			wait_on_buffer(bh);
			goto wait_for_ctlbuf;
		}
		if (cond_resched())
			goto wait_for_ctlbuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
		/* 从链表中摘除 */
		journal_unfile_buffer(journal, jh);
		journal_put_journal_head(jh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	/**
	 * 运行到此，所有数据块已经保存到磁盘中。
	 * 并且元数据已经保存到日志中。
	 */
	jbd_debug(3, "JBD: commit phase 6\n");

	if (is_journal_aborted(journal))
		goto skip_commit;

	/* Done it all: now write the commit record.  We should have
	 * cleaned up our previous buffers by now, so if we are in abort
	 * mode we can now just skip the rest of the journal write
	 * entirely. */

	/**
	 * 获得一个日志描述符。
	 * 该描述符标记事务已经提交。
	 */
	descriptor = journal_get_descriptor_buffer(journal);
	if (!descriptor) {
		__journal_abort_hard(journal);
		goto skip_commit;
	}

	/* AKPM: buglet - add `i' to tmp! */
	/**
	 * 标记描述符，表示它是一个提交描述符。
	 */
	for (i = 0; i < jh2bh(descriptor)->b_size; i += 512) {
		journal_header_t *tmp =
			(journal_header_t*)jh2bh(descriptor)->b_data;
		tmp->h_magic = cpu_to_be32(JFS_MAGIC_NUMBER);
		tmp->h_blocktype = cpu_to_be32(JFS_COMMIT_BLOCK);
		tmp->h_sequence = cpu_to_be32(commit_transaction->t_tid);
	}

	JBUFFER_TRACE(descriptor, "write commit block");
	{
		struct buffer_head *bh = jh2bh(descriptor);
		int ret;
		int barrier_done = 0;

		set_buffer_dirty(bh);
		if (journal->j_flags & JFS_BARRIER) {
			/* 必须标记本次IO的屏障属性
			 * 防止与前面的操作乱序
			 */
			set_buffer_ordered(bh);
			barrier_done = 1;
		}
		/**
		 * 将提交描述符写入到日志中。
		 */
		ret = sync_dirty_buffer(bh);
		/* is it possible for another commit to fail at roughly
		 * the same time as this one?  If so, we don't want to
		 * trust the barrier flag in the super, but instead want
		 * to remember if we sent a barrier request
		 */
		/**
		 * EOPNOTSUPP表示设备不支持屏障操作
		 * 这时，我们也没有办法
		 * 另外一种可能性，是它本身就不乱序
		 */
		if (ret == -EOPNOTSUPP && barrier_done) {
			char b[BDEVNAME_SIZE];

			printk(KERN_WARNING
				"JBD: barrier-based sync failed on %s - "
				"disabling barriers\n",
				bdevname(journal->j_dev, b));
			spin_lock(&journal->j_state_lock);
			/**
			 * 设备不支持，去除此标志
			 * 自求多福吧，我们暂且认为设备不会乱序
			 * 实际上，目前很少有设备会乱序
			 */
			journal->j_flags &= ~JFS_BARRIER;
			spin_unlock(&journal->j_state_lock);

			/* And try again, without the barrier */
			/* 清除标记后再次提交 */
			clear_buffer_ordered(bh);
			set_buffer_uptodate(bh);
			set_buffer_dirty(bh);
			ret = sync_dirty_buffer(bh);
		}
		if (unlikely(ret == -EIO))
			err = -EIO;
		put_bh(bh);		/* One for getblk() */
		/* 可以释放journal_head资源了 */
		journal_put_journal_head(descriptor);
	}

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */

	/**
	 * 提交块已经写入完毕，现在可以进行checkpoint处理了。
	 */
skip_commit: /* The journal should be unlocked by now. */

	if (err)
		__journal_abort_hard(journal);

	jbd_debug(3, "JBD: commit phase 7\n");

	J_ASSERT(commit_transaction->t_sync_datalist == NULL);
	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_iobuf_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);
	J_ASSERT(commit_transaction->t_log_list == NULL);

restart_loop:
	/**
	 * 当前事务与前面的事务存在一定的关联关系。
	 * 当前事务的元数据，与前面事务的元数据区相关。
	 */
	while (commit_transaction->t_forget) {
		transaction_t *cp_transaction;
		struct buffer_head *bh;

		jh = commit_transaction->t_forget;
		bh = jh2bh(jh);
		jbd_lock_bh_state(bh);
		J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction ||
			jh->b_transaction == journal->j_running_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 */
		/**
		 * 释放其持有的备份数据。
		 */
		if (jh->b_committed_data) {
			kfree(jh->b_committed_data);
			jh->b_committed_data = NULL;
			if (jh->b_frozen_data) {
				jh->b_committed_data = jh->b_frozen_data;
				jh->b_frozen_data = NULL;
			}
		} else if (jh->b_frozen_data) {
			kfree(jh->b_frozen_data);
			jh->b_frozen_data = NULL;
		}

		spin_lock(&journal->j_list_lock);
		/**
		 * 上一个事务在用此缓冲区
		 * 首先将它摘除下来
		 * 稍后放到当前事务的checkpoint链表中
		 */
		cp_transaction = jh->b_cp_transaction;
		if (cp_transaction) {
			JBUFFER_TRACE(jh, "remove from old cp transaction");
			__journal_remove_checkpoint(jh);
		}

		/* Only re-checkpoint the buffer_head if it is marked
		 * dirty.  If the buffer was added to the BJ_Forget list
		 * by journal_forget, it may no longer be dirty and
		 * there's no point in keeping a checkpoint record for
		 * it. */

		/* A buffer which has been freed while still being
		 * journaled by a previous transaction may end up still
		 * being dirty here, but we want to avoid writing back
		 * that buffer in the future now that the last use has
		 * been committed.  That's not only a performance gain,
		 * it also stops aliasing problems if the buffer is left
		 * behind for writeback and gets reallocated for another
		 * use in a different page. */
		if (buffer_freed(bh)) {
			clear_buffer_freed(bh);
			clear_buffer_jbddirty(bh);
		}

		if (buffer_jbddirty(bh)) {
			JBUFFER_TRACE(jh, "add to new checkpointing trans");
			/* 加入到事务的checkpoint链表 */
			__journal_insert_checkpoint(jh, commit_transaction);
			JBUFFER_TRACE(jh, "refile for checkpoint writeback");
			__journal_refile_buffer(jh);
			jbd_unlock_bh_state(bh);
		} else {/* 不脏，也就不用加入到checkpoint链表了 */
			J_ASSERT_BH(bh, !buffer_dirty(bh));
			J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
			/* 从现有链表中摘除，并释放 */
			__journal_unfile_buffer(jh);
			jbd_unlock_bh_state(bh);
			journal_remove_journal_head(bh);  /* needs a brelse */
			release_buffer_page(bh);
		}
		spin_unlock(&journal->j_list_lock);
		if (cond_resched())
			goto restart_loop;
	}

	/* Done with this transaction! */

	jbd_debug(3, "JBD: commit phase 8\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT);

	/*
	 * This is a bit sleazy.  We borrow j_list_lock to protect
	 * journal->j_committing_transaction in __journal_remove_checkpoint.
	 * Really, __jornal_remove_checkpoint should be using j_state_lock but
	 * it's a bit hassle to hold that across __journal_remove_checkpoint
	 */
	spin_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/**
	 * 标记当前事务处理完成。
	 */
	commit_transaction->t_state = T_FINISHED;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	/**
	 * 记录提交点。
	 */
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL;
	spin_unlock(&journal->j_state_lock);

	/**
	 * 将事务链接到日志的checkpoint链表中
	 */
	if (commit_transaction->t_checkpoint_list == NULL) {
		__journal_drop_transaction(journal, commit_transaction);
	} else {
		if (journal->j_checkpoint_transactions == NULL) {
			journal->j_checkpoint_transactions = commit_transaction;
			commit_transaction->t_cpnext = commit_transaction;
			commit_transaction->t_cpprev = commit_transaction;
		} else {
			commit_transaction->t_cpnext =
				journal->j_checkpoint_transactions;
			commit_transaction->t_cpprev =
				commit_transaction->t_cpnext->t_cpprev;
			commit_transaction->t_cpnext->t_cpprev =
				commit_transaction;
			commit_transaction->t_cpprev->t_cpnext =
				commit_transaction;
		}
	}
	/**
	 * 注意
	 * 这里并不处理checkpoint
	 * 当日志没有空间，或者umount时
	 * 才会真正去等待checkpoint以回收日志空间
	 * 也就是说，内存中有不少buffer_head对象
	 */
	spin_unlock(&journal->j_list_lock);

	jbd_debug(1, "JBD: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	wake_up(&journal->j_wait_done_commit);
}
