// #ifndef USERPROG_SYSCALL_H
// #define USERPROG_SYSCALL_H
// #include <list.h>

// void syscall_init(void);

// struct lock file_lock;
// #endif /* userprog/syscall.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

// project 2-4. file descriptor
struct lock file_rw_lock;

#endif /* userprog/syscall.h */
