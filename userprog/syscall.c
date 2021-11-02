#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/fat.h"
#include "filesys/directory.h"
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
#include "string.h"

const int STDIN = 1;
const int STDOUT = 2;

void syscall_init(void);
void syscall_entry(void);
void syscall_handler(struct intr_frame *);

static struct file *find_file_by_fd(int fd);

struct page *check_address(void *addr);
void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write);

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

	lock_init(&filesys_lock);
}

void syscall_handler(struct intr_frame *f) {
#ifdef VM
	thread_current() -> rsp_stack = f -> rsp;
#endif

	uint64_t number = f -> R.rax;

	switch (f -> R.rax) {
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			exit(f -> R.rdi);
			break;

		case SYS_FORK:
			// memcpy(&thread_current() -> fork_tf, f, sizeof(struct intr_frame));
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
		
		case SYS_ISDIR:
			f -> R.rax = is_dir(f -> R.rdi);
			break;
		
		case SYS_CHDIR:
			f -> R.rax = sys_chdir(f -> R.rdi);
			break;
		
		case SYS_MKDIR:
			f -> R.rax = sys_mkdir(f -> R.rdi);
			break;
		
		case SYS_READDIR:
			f -> R.rax = sys_readdir(f -> R.rdi, f -> R.rsi);
			break;
		
		case SYS_INUMBER:
			f -> R.rax = sys_inumber(f -> R.rdi);
			break;
		
		case SYS_SYMLINK:
			f -> R.rax = symlink(f -> R.rdi, f -> R.rsi);
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
	lock_acquire(&filesys_lock);

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

	lock_release(&filesys_lock);
	return ret;
}

int write(int fd, const void *buffer, unsigned size) {
	lock_acquire(&filesys_lock);

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

	lock_release(&filesys_lock);
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

bool is_dir(int fd) {
	struct file *target = find_file_by_fd(fd);

	if (target == NULL)
		return false;
	
	return inode_is_dir(file_get_inode(target));
}

bool sys_chdir(const char *path_name) {
	if (path_name == NULL)
		return false;
	
	char *cp_name = (char *)malloc(strlen(path_name) + 1);

	strlcpy(cp_name, path_name, strlen(path_name) + 1);

	struct dir *chdir = NULL;

	if (cp_name[0] == '/')
		chdir = dir_open_root();
	
	else
		chdir = dir_reopen(thread_current() -> curr_dir);
	
	struct inode *inode = NULL;
	char *token, *next_token, *save_ptr;

	token = strtok_r(cp_name, "/", &save_ptr);

	while (token != NULL) {
		if (!dir_lookup(chdir, token, &inode)) {
			dir_close(chdir);

			return false;
		}

		if (!inode_is_dir(inode)) {
			dir_close(chdir);

			return false;
		}

		dir_close(chdir);
		chdir = dir_open(inode);
		token = strtok_r(NULL, "/", &save_ptr);
	}

	dir_close(thread_current() -> curr_dir);
	thread_current() -> curr_dir = chdir;
	free(cp_name);

	return true;
}

bool sys_mkdir(const char *dir) {
	lock_acquire(&filesys_lock);

	bool tmp = filesys_create_dir(dir);

	lock_release(&filesys_lock);

	return tmp;
}

bool sys_readdir(int fd, char *name) {
	if (name == NULL)
		return false;
	
	struct file *target = find_file_by_fd(fd);

	if (target == NULL)
		return false;
	
	if (!inode_is_dir(file_get_inode(target)))
		return false;
	
	struct dir *p_file = target;

	if (p_file -> pos == 0)
		dir_seek(p_file, 2 * sizeof(struct dir_entry));
	
	bool result = dir_readdir(p_file, name);

	return result;
}

struct cluster_t *sys_inumber(int fd) {
	struct file *target = find_file_by_fd(fd);

	if (target == NULL)
		return false;
	
	return inode_get_inumber(file_get_inode(target));
}

int symlink(const char *target, const char *link_path) {
	bool success = false;
	char *cp_link = (char *)malloc(strlen(link_path) + 1);

	strlcpy(cp_link, link_path, strlen(link_path) + 1);

	char *file_link = (char *)malloc(strlen(cp_link) + 1);
	struct dir *dir = parse_path(cp_link, file_link);

	cluster_t inode_cluster = fat_create_chain(0);

	success = (dir != NULL
			&& link_inode_create(inode_cluster, target)
			&& dir_add(dir, file_link, inode_cluster));
	
	if (!success && inode_cluster != 0)
		fat_remove_chain(inode_cluster, 0);
	
	dir_close(dir);
	free(cp_link);
	free(file_link);

	return success - 1;
}