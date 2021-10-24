// #ifndef USERPROG_PROCESS_H
// #define USERPROG_PROCESS_H

// #include "threads/thread.h"
// #include "filesys/off_t.h"

// static void process_init(void);
// tid_t process_create_initd(const char *file_name);
// static void initd(void *f_name);
// struct thread *get_child_process(int pid);

// tid_t process_fork(const char *name, struct intr_frame *if_);
// static bool duplicate_pte (uint64_t *pte, void *va, void *aux);
// static void __do_fork(void *aux);

// int process_exec(void *f_name);
// int process_wait(tid_t child_tid UNUSED);

// void process_exit (void);
// static void process_cleanup(void);
// void process_activate(struct thread *next);

// static bool load(const char *file_name, struct intr_frame *if_);
// static bool install_page(void *upage, void *kpage, bool writable);
// static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
// static bool setup_stack(struct intr_frame *if_);
// static bool install_page(void *upage, void *kpage, bool writable);

// void argument_stack(char **argv, int argc, void **rspp);

// #endif /* userprog/process.h */

#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct box {
    struct file *file;
    off_t ofs;
    size_t page_read_bytes;
};

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

struct thread *get_child_process(int pid);

bool install_page(void *upage, void *kpage, bool writable);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool setup_stack(struct intr_frame *if_);

#endif /* userprog/process.h */