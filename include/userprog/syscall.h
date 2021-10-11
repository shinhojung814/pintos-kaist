#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>

struct file {
	struct inode *inode;        /* File's inode. */
	// off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
    int dup_count;
};

void syscall_init (void);

struct lock file_rw_lock;

#endif /* userprog/syscall.h */