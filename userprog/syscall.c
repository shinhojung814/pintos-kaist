#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "intrinsic.h"

const int STDIN = 1;
const int STDOUT = 2;

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

static struct file *find_file_by_fd(int fd);

struct page *check_address(void *addr);
void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write);

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
void munmap(void *addp);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&file_lock);
}

void syscall_handler(struct intr_frame *f) {
#ifdef VM
	thread_current() -> rsp_stack = f -> rsp;
#endif

	switch (f -> R.rax) {
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			exit(f -> R.rdi);
			break;

		case SYS_FORK:
			f -> R.rax = fork(f -> R.rdi, f);
			break;

		case SYS_EXEC:
			if (exec(f -> R.rdi) == -1)
				exit(-1);
			break;
		
		case SYS_WAIT:
			f -> R.rax = wait(f -> R.rdi);
			break;
		
		case SYS_CREATE:
			f -> R.rax = create(f -> R.rdi, f -> R.rsi);
			break;
		
		case SYS_REMOVE:
			f -> R.rax = remove(f -> R.rdi);
			break;
		
		case SYS_OPEN:
			f -> R.rax = open(f -> R.rdi);
			break;
		
		case SYS_FILESIZE:
			f -> R.rax = filesize(f -> R.rdi);
			break;
		case SYS_READ:
			check_valid_buffer(f -> R.rsi, f -> R.rdx, f -> rsp, 1);
			f -> R.rax = read(f -> R.rdi, f -> R.rsi, f -> R.rdx);
			break;
		
		case SYS_WRITE:
			check_valid_buffer(f -> R.rsi, f -> R.rdx, f -> rsp, 0);
			f -> R.rax = write(f -> R.rdi, f -> R.rsi, f -> R.rdx);
			break;
		
		case SYS_SEEK:
			seek(f -> R.rdi, f -> R.rsi);
			break;
		
		case SYS_TELL:
			f -> R.rax = tell(f -> R.rdi);
			break;
		
		case SYS_CLOSE:
			close(f -> R.rdi);
			break;
		
		case SYS_DUP2:
			f -> R.rax = dup2(f -> R.rdi, f -> R.rsi);
			break;
		
		case SYS_MMAP:
			f -> R.rax = mmap(f -> R.rdi, f -> R.rsi, f -> R.rdx, f -> R.r10, f -> R.r8);
			break;
		
		case SYS_MUNMAP:
			munmap(f -> R.rdi);
			break;
		
		default:
			exit(-1);
			break;
	}
}

struct page *check_address(void *addr) {
	if (is_kernel_vaddr(addr))
		exit(-1);
	
	return spt_find_page(&thread_current() -> spt, addr);
}

void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write) {
	for (int i = 0; i < size; i++) {
		struct page *page = check_address(buffer + i);

		if (page == NULL)
			exit(-1);
		
		if (to_write == true && page -> writable == false)
			exit(-1);
	}
}

static struct file *find_file_by_fd(int fd) {
	struct thread *curr = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;

	return curr -> fd_table[fd];
}

int add_file_to_fdt(struct file *file) {
	struct thread *curr = thread_current();
	struct file **fdt = curr -> fd_table;

	while (curr -> fd_idx < FDCOUNT_LIMIT && fdt[curr -> fd_idx])
		curr -> fd_idx++;

	if (curr -> fd_idx >= FDCOUNT_LIMIT)
		return -1;

	fdt[curr -> fd_idx] = file;
	return curr -> fd_idx;
}

void remove_file_from_fdt(int fd) {
	struct thread *curr = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	curr -> fd_table[fd] = NULL;
}

void halt(void) {
	power_off();
}

void exit(int status) {
	struct thread *curr = thread_current();

	curr -> exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int exec(char *file_name) {
	check_address(file_name);

	int file_size = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if (fn_copy == NULL)
		exit(-1);
	
	strlcpy(fn_copy, file_name, file_size);

	if (process_exec(fn_copy) == -1)
		return -1;

	NOT_REACHED();
	return 0;
}

int wait(tid_t tid) {
	return process_wait(tid);
}

bool create(const char *file, unsigned initial_size) {
	if (file)
		return filesys_create(file, initial_size);
	else
		exit(-1);
}

bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file) {
	check_address(file);

	if (file == NULL)
		return -1;

	struct file *file_object = filesys_open(file);

	if (file_object == NULL)
		return -1;

	int fd = add_file_to_fdt(file_object);

	if (fd == -1)
		file_close(file_object);

	return fd;
}

int filesize(int fd) {
	struct file *file_object = find_file_by_fd(fd);

	if (file_object == NULL)
		return -1;
	
	return file_length(file_object);
}

int read(int fd, void *buffer, unsigned size) {
	struct thread *curr = thread_current();
	struct file *file_object = find_file_by_fd(fd);
	int ret;

	if (file_object == NULL)
		return -1;

	if (file_object == STDIN) {
		if (curr -> stdin_count == 0) {
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}

		else {
			int i;
			unsigned char *buf = buffer;

			for (i = 0; i < size; i++) {
				char c = input_getc();
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}

	else if (file_object == STDOUT) {
		ret = -1;
	}

	else {
		lock_acquire(&file_lock);
		ret = file_read(file_object, buffer, size);
		lock_release(&file_lock);
	}

	return ret;
}

int write(int fd, const void *buffer, unsigned size) {
	struct file *file_object = find_file_by_fd(fd);
	int ret;

	if (file_object == NULL)
		return -1;

	struct thread *curr = thread_current();

	if (file_object == STDOUT) {
		if (curr -> stdout_count == 0) {
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}

		else {
			putbuf(buffer, size);
			ret = size;
		}
	}

	else if (file_object == STDIN) {
		ret = -1;
	}
	
	else {
		lock_acquire(&file_lock);
		ret = file_write(file_object, buffer, size);
		lock_release(&file_lock);
	}

	return ret;
}

void seek(int fd, unsigned position) {
	struct file *file_object = find_file_by_fd(fd);

	if (file_object <= 2)
		return;
	
	file_object -> pos = position;
}

unsigned tell(int fd) {
	struct file *file_object = find_file_by_fd(fd);

	if (file_object <= 2)
		return;
	
	return file_tell(file_object);
}

void close(int fd) {
	struct file *file_object = find_file_by_fd(fd);

	if (file_object == NULL)
		return;

	struct thread *curr = thread_current();

	if (fd == 0 || file_object == STDIN) {
		curr -> stdin_count--;
	}

	else if (fd == 1 || file_object == STDOUT) {
		curr -> stdout_count--;
	}

	remove_file_from_fdt(fd);

	if (fd <= 1 || file_object <= 2)
		return;

	if (file_object -> dup_count == 0)
		file_close(file_object);
	
	else
		file_object -> dup_count--;
}

int dup2(int old_fd, int new_fd) {
	struct file *file_object = find_file_by_fd(old_fd);

	if (file_object == NULL)
		return -1;

	struct file *deadfile = find_file_by_fd(new_fd);

	if (old_fd == new_fd)
		return new_fd;

	struct thread *curr = thread_current();
	struct file **fdt = curr -> fd_table;

	if (file_object == STDIN)
		curr -> stdin_count++;
	
	else if (file_object == STDOUT)
		curr -> stdout_count++;
	
	else
		file_object -> dup_count++;

	close(new_fd);
	fdt[new_fd] = file_object;
	return new_fd;
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
	if (offset % PGSIZE != 0)
		return NULL;
	
	if (pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <= 0)
		return NULL;
	
	if (fd == 0 || fd == 1)
		exit(-1);
	
	if (spt_find_page(&thread_current() -> spt, addr))
		return NULL;
	
	struct file *target = find_file_by_fd(fd);

	if (target == NULL)
		return NULL;
	
	void *ret = do_mmap(addr, length, writable, target, offset);

	return ret;
}

void munmap(void *addr) {
	do_munmap(addr);
}