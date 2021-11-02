#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>

void syscall_init(void);

void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int dup2(int old_fd, int new_fd);
void *mmap(void *addr, size_t size, int writable, int fd, off_t offset);
void munmap(void *addr);

bool is_dir(int fd);
bool sys_chdir(const char *path_name);
bool sys_mkdir(const char *dir);
bool sys_readdir(int fd, char *name);
struct cluster_t *sys_inumber(int fd);
int symlink(const char *target, const char *link_path);

struct lock file_lock;
#endif /* userprog/syscall.h */