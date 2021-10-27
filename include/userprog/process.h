#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

struct container {
    struct file *file;
    off_t offset;
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
bool lazy_load_segment(struct page *page, void *aux);
bool setup_stack(struct intr_frame *if_);

#endif /* userprog/process.h */