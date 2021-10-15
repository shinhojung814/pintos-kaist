// #ifndef USERPROG_SYSCALL_H
// #define USERPROG_SYSCALL_H
// #include <list.h>

// void syscall_init(void);

// struct lock file_lock;

// #endif /* userprog/syscall.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>

void syscall_init(void);

// Project 2-4. File descriptor
struct lock file_rw_lock; // prevent simultaneous read, write (race condition prevention?)

#endif /* userprog/syscall.h */
