// #include <stdio.h>
// #include <list.h>
// #include <syscall-nr.h>
// #include "userprog/syscall.h"
// #include "userprog/process.h"
// #include "userprog/gdt.h"
// #include "threads/interrupt.h"
// #include "threads/thread.h"
// #include "threads/loader.h"
// #include "threads/palloc.h"
// #include "threads/flags.h"
// #include "threads/vaddr.h"
// #include "filesys/filesys.h"
// #include "filesys/file.h"
// #include "intrinsic.h"

// const int STDIN = 1;
// const int STDOUT = 2;

// void syscall_entry(void);
// void syscall_handler(struct intr_frame *);

// void halt(void);
// void exit(int status);
// bool create(const char *file, unsigned initial_size);
// bool remove(const char *file);

// tid_t fork(const char *thread_name, struct intr_frame *f);
// int exec(char *file_name);
// int open(const char *file);
// int filesize(int fd);
// int read(int fd, void *buffer, unsigned size);
// int write(int fd, const void *buffer, unsigned size);
// void seek(int fd, unsigned position);
// unsigned tell(int fd);
// void close(int fd);

// void check_address(const uint64_t *uaddr);
// int process_add_file(struct file *file);
// static struct file *process_get_file(int fd);
// void process_close_file(int fd);
// int dup2(int old_fd, int new_fd);

// /* System call.
//  *
//  * Previously system call services was handled by the interrupt handler
//  * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
//  * efficient path for requesting the system call, the `syscall` instruction.
//  *
//  * The syscall instruction works by reading the values from the the Model
//  * Specific Register (MSR). For the details, see the manual. */

// #define MSR_STAR 0xc0000081         /* Segment selector msr */
// #define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
// #define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// void syscall_init(void) {
// 	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
// 	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

// 	/* The interrupt service rountine should not serve any interrupts
// 	 * until the syscall_entry swaps the userland stack to the kernel
// 	 * mode stack. Therefore, we masked the FLAG_FL. */
// 	write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

// 	lock_init(&file_lock);
// }

// /* The main system call interface */
// void syscall_handler(struct intr_frame *f) {
// 	switch (f -> R.rax) {
// 		case SYS_HALT:
// 			halt();
// 			break;

// 		case SYS_EXIT:
// 			exit(f -> R.rdi);
// 			break;

// 		case SYS_FORK:
// 			f -> R.rax = fork(f -> R.rdi, f);
// 			break;
		
// 		case SYS_EXEC:
// 			if (exec(f -> R.rdi) == -1)
// 				exit(-1);
// 			break;
		
// 		case SYS_WAIT:
// 			f -> R.rax = process_wait(f -> R.rdi);
// 			break;
		
// 		case SYS_CREATE:
// 			f -> R.rax = create(f -> R.rdi, f -> R.rsi);
// 			break;
		
// 		case SYS_REMOVE:
// 			f-> R.rax = remove(f -> R.rdi);
// 			break;
		
// 		case SYS_OPEN:
// 			f -> R.rax = open(f -> R.rdi);
// 			break;
		
// 		case SYS_FILESIZE:
// 			f -> R.rax = filesize(f -> R.rdi);
// 			break;
		
// 		case SYS_READ:
// 			f -> R.rax = read(f -> R.rdi, f -> R.rsi, f -> R.rdx);
// 			break;
		
// 		case SYS_WRITE:
// 			f -> R.rax = write(f -> R.rdi, f -> R.rsi, f -> R.rdx);
// 			break;
		
// 		case SYS_SEEK:
// 			seek(f -> R.rdi, f -> R.rsi);
// 			break;

// 		case SYS_TELL:
// 			f -> R.rax = tell(f -> R.rdi);
// 			break;
		
// 		case SYS_CLOSE:
// 			close(f -> R.rdi);
// 			break;
		
// 		case SYS_DUP2:
// 			f -> R.rax = dup2(f -> R.rdi, f -> R.rsi);
// 			break;
		
// 		default:
// 			exit(-1);
// 			break;
// 	}
// }

// /* Terminates the operating system by calling power_off() */
// void halt(void) {
// 	power_off();
// }

// /* Ends current thread and returns name and status number of the thread */
// void exit(int status) {
// 	struct thread *curr = thread_current();

// 	curr -> exit_status = status;

// 	printf("%s: exit(%d)\n", thread_name(), status);
// 	thread_exit();
// }

// /* Checks validity of given user virtual address */
// void check_address(const uint64_t *uaddr) {
// 	struct thread *curr = thread_current();

// 	if (uaddr == NULL || !(is_user_vaddr(uaddr)) || pml4_get_page(curr -> pml4, uaddr) == NULL) {
// 		exit(-1);
// 	}
// }

// /* Creates a new file and returns initial size in bytes */
// bool create(const char *file, unsigned initial_size) {
// 	check_address(file);
// 	return filesys_create(file, initial_size);
// }

// /* Deletes a file and returns true if done successfully */
// bool remove(const char *file) {
// 	check_address(file);
// 	return filesys_remove(file);
// }

// int process_add_file(struct file *file) {
// 	struct thread *curr = thread_current();
// 	struct file **fdt = curr ->fd_table;

// 	while (curr -> fd_idx < FDCOUNT_LIMIT && fdt[curr -> fd_idx])
// 		curr -> fd_idx++;
	
// 	if (curr -> fd_idx >= FDCOUNT_LIMIT)
// 		return -1;
	
// 	fdt[curr -> fd_idx] = file;
// 	return curr -> fd_idx;
// }

// static struct file *process_get_file(int fd) {
// 	struct thread *curr = thread_current();

// 	if (fd <= 0 || fd >= FDCOUNT_LIMIT)
// 		return NULL;
	
// 	return curr -> fd_table[fd];
// }

// void process_close_file(int fd) {
// 	struct thread *curr = thread_current();

// 	if (fd < 0 || fd >= FDCOUNT_LIMIT)
// 		return;
	
// 	curr -> fd_table[fd] = NULL;
// }

// /* Opens a file and returns fd if done successfully */
// int open(const char *file) {
// 	check_address(file);

// 	struct file *file_object = filesys_open(file);

// 	if (file_object == NULL)
// 		return -1;

// 	int fd = process_add_file(file_object);

// 	if (fd == -1)
// 		file_close(file_object);
	
// 	return fd;
// }

// /* Returns a size of opened file as fd */
// int filesize(int fd) {
// 	struct file *file_object = process_get_file(fd);

// 	if (file_object == NULL)
// 		return -1;
	
// 	return file_length(file_object);
// }

// /* Reads size bytes from the file opened as fd into buffer and returns the number of bytes read */
// int read(int fd, void *buffer, unsigned size) {
// 	check_address(buffer);

// 	int bytes;
// 	struct thread *curr = thread_current();

// 	struct file *file_object = process_get_file(fd);

// 	if (file_object == NULL)
// 		return -1;
	
// 	if (file_object == STDIN) {
// 		if (curr -> stdin_count == 0) {
// 			NOT_REACHED();
// 			process_close_file(fd);
// 			bytes = -1;
// 		}

// 		else {
// 			int i;
// 			unsigned char *buf = buffer;

// 			for (i = 0; i < size; i++) {
// 				char c = input_getc();
// 				*buf++ = c;

// 				if (c == '\0')
// 					break;
// 			}
// 			bytes = i;
// 		}
// 	}

// 	else if (file_object == STDOUT) {
// 		bytes = -1;
// 	}

// 	else {
// 		lock_acquire(&file_lock);
// 		bytes = file_read(file_object, buffer, size);
// 		lock_release(&file_lock);
// 	}
// 	return bytes;
// }

// /* Writes size bytes from buffer to the open file and return the number of bytes written */
// int write(int fd, const void *buffer, unsigned size) {
// 	check_address(buffer);

// 	int bytes;
// 	struct file *file_object = process_get_file(fd);

// 	if (file_object = NULL)
// 		return -1;
	
// 	struct thread *curr = thread_current();

// 	if (file_object == STDOUT) {
// 		if (curr -> stdout_count == 0) {
// 			NOT_REACHED();
// 			process_close_file(fd);
// 			bytes = -1;
// 		}

// 		else {
// 			putbuf(buffer, size);
// 			bytes = size;
// 		}
// 	}

// 	else if (file_object == STDIN) {
// 		bytes = -1;
// 	}

// 	else {
// 		lock_acquire(&file_lock);
// 		bytes = file_write(file_object, buffer, size);
// 		lock_release(&file_lock);
// 	}

// 	return bytes;
// }

// /* Changes the next byte to be read or written in open file fd to position */
// void seek(int fd, unsigned position) {
// 	struct file *file_object = process_get_file(fd);

// 	if (file_object <= 2)
// 		return;
	
// 	file_object -> pos = position;
// }

// /* Returns the position of the next byte to be read or written in open file fd */
// unsigned tell(int fd) {
// 	struct file *file_object = process_get_file(fd);

// 	if (file_object <= 2)
// 		return;
	
// 	return file_tell(file_object);
// }

// /* Closes file descriptor fd */
// void close(int fd) {
// 	struct file *file_object = process_get_file(fd);

// 	if (file_object == NULL)
// 		return;
	
// 	struct thread *curr = thread_current();

// 	if (fd == 0 || file_object == STDIN) {
// 		curr -> stdin_count--;
// 	}

// 	else if (fd == 1 || file_object == STDOUT) {
// 		curr -> stdout_count--;
// 	}

// 	process_close_file(fd);

// 	if (fd <= 1 || file_object <= 2)
// 		return;
	
// 	if (file_object -> dup_count == 0)
// 		file_close(file_object);
	
// 	else
// 		file_object -> dup_count--;
// }

// /* Creates a copy of old_fd into new_fd and closes new_fd if it is open */
// int dup2(int old_fd, int new_fd) {
// 	struct file *file_object = process_get_file(old_fd);

// 	if (file_object == NULL)
// 		return -1;
	
// 	struct file *dead_file = process_get_file(new_fd);

// 	if (old_fd == new_fd)
// 		return new_fd;
	
// 	struct thread *curr = thread_current();
// 	struct file **fdt = curr -> fd_table;

// 	/* Copy STDIN or STDOUT to another file descriptor */
// 	if (file_object == STDIN)
// 		curr -> stdin_count++;
	
// 	else if (file_object == STDOUT)
// 		curr -> stdout_count++;
	
// 	else
// 		file_object -> dup_count++;
	
// 	close(new_fd);
// 	fdt[new_fd] = file_object;
	
// 	return new_fd;
// }

// /* Creates a child thread and returns PID of child if done successfully */
// tid_t fork(const char *thread_name, struct intr_frame *f) {
// 	return process_fork(thread_name, f);
// }

// /* Runs executable files from current process return -1 if not done successfully */
// int exec(char *file_name) {
// 	check_address(file_name);

// 	int file_size = strlen(file_name) + 1;
// 	char *fn_copy = palloc_get_page(PAL_ZERO);

// 	if (fn_copy == NULL) {
// 		exit(-1);
// 	}

// 	strlcpy(fn_copy, file_name, file_size);

// 	if (process_exec(fn_copy) == -1)
// 		return -1;
	
// 	NOT_REACHED();
// 	return 0;
// }

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/flags.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

// Project2-4 File descriptor
static struct file *find_file_by_fd(int fd);
// Project2-extra
const int STDIN = 1;
const int STDOUT = 2;

void check_address(uaddr);
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
int dup2(int oldfd, int newfd);

// #define DEBUG

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

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	// Project 2-4. File descriptor
	lock_init(&file_rw_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
	char *fn_copy;
	int siz;

	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		if (exec(f->R.rdi) == -1)
			exit(-1);
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_DUP2:
		f->R.rax = dup2(f->R.rdi, f->R.rsi);
		break;
	default:
		exit(-1);
		break;
	}

	//thread_exit();
}

// Check validity of given user virtual address. Exits if any of below conditions is met.
// 1. Null pointer
// 2. A pointer to kernel virtual address space (above KERN_BASE)
// 3. A pointer to unmapped virtual memory (causes page_fault)
void check_address(const uint64_t *uaddr)
{
	struct thread *cur = thread_current();
	if (uaddr == NULL || !(is_user_vaddr(uaddr)) || pml4_get_page(cur->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

// Project 2-4. File descriptor
// Check if given fd is valid, return cur->fdTable[fd]
static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;

	return cur->fdTable[fd]; // automatically returns NULL if empty
}

// Find open spot in current thread's fdt and put file in it. Returns the fd.
int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable; // file descriptor table

	// Project2-extra - (multi-oom) Find open spot from the front
	while (cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx])
		cur->fdIdx++;

	// Error - fdt full
	if (cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

// Check for valid fd and do cur->fdTable[fd] = NULL. Returns nothing
void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fdTable[fd] = NULL;
}

// Project 2-2. syscalls

// Terminates Pintos by calling power_off(). No return.
void halt(void)
{
	power_off();
}

// End current thread, record exit statusNo return.
void exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status); // Process Termination Message
	thread_exit();
}

// Creates a new file called file initially initial_size bytes in size.
// Returns true if successful, false otherwise
bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

// Deletes the file called 'file'. Returns true if successful, false otherwise.
bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

// Opens the file called file, returns fd or -1 (if file could not be opened for some reason)
int open(const char *file)
{
	check_address(file);
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL)
		return -1;

	int fd = add_file_to_fdt(fileobj);

	// FD table full
	if (fd == -1)
		file_close(fileobj);

	return fd;
}

// Returns the size, in bytes, of the file open as fd.
int filesize(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

// Reads size bytes from the file open as fd into buffer.
// Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read
int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int ret;
	struct thread *cur = thread_current();

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;

	if (fileobj == STDIN)
	{
		if (cur->stdin_count == 0)
		{
			// Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			int i;
			unsigned char *buf = buffer;
			for (i = 0; i < size; i++)
			{
				char c = input_getc();
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}
	else if (fileobj == STDOUT)
	{
		ret = -1;
	}
	else
	{
		// Q. read는 동시접근 허용해도 되지 않을까?
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

// Writes size bytes from buffer to the open file fd.
// Returns the number of bytes actually written, or -1 if the file could not be written
int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	int ret;

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;

	struct thread *cur = thread_current();

	if (fileobj == STDOUT)
	{
		if (cur->stdout_count == 0)
		{
			// Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			putbuf(buffer, size);
			ret = size;
		}
	}
	else if (fileobj == STDIN)
	{
		ret = -1;
	}
	else
	{
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}

	return ret;
}

// Changes the next byte to be read or written in open file fd to position,
// expressed in bytes from the beginning of the file (Thus, a position of 0 is the file's start).
void seek(int fd, unsigned position)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	fileobj->pos = position;
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
unsigned tell(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	return file_tell(fileobj);
}

// Closes file descriptor fd. Ignores NULL file. Returns nothing.
void close(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return;

	struct thread *cur = thread_current();

	if (fd == 0 || fileobj == STDIN)
	{
		cur->stdin_count--;
	}
	else if (fd == 1 || fileobj == STDOUT)
	{
		cur->stdout_count--;
	}

	remove_file_from_fdt(fd);
	if (fd <= 1 || fileobj <= 2)
		return;

	if (fileobj->dupCount == 0)
		file_close(fileobj);
	else
		fileobj->dupCount--;
}

// Creates 'copy' of oldfd into newfd. If newfd is open, close it. Returns newfd on success, -1 on fail (invalid oldfd)
// After dup2, oldfd and newfd 'shares' struct file, but closing newfd should not close oldfd (important!)
int dup2(int oldfd, int newfd)
{
	struct file *fileobj = find_file_by_fd(oldfd);
	if (fileobj == NULL)
		return -1;

	struct file *deadfile = find_file_by_fd(newfd);

	if (oldfd == newfd)
		return newfd;

	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	// Don't literally copy, but just increase its count and share the same struct file
	// [syscall close] Only close it when count == 0

	// Copy stdin or stdout to another fd
	if (fileobj == STDIN)
		cur->stdin_count++;
	else if (fileobj == STDOUT)
		cur->stdout_count++;
	else
		fileobj->dupCount++;

	close(newfd);
	fdt[newfd] = fileobj;
	return newfd;
}

// (parent) Returns pid of child on success or -1 on fail
// (child) Returns 0
tid_t fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

// Run new 'executable' from current process
// Don't confuse with open! 'open' just opens up any file (txt, executable), 'exec' runs only executable
// Never returns on success. Returns -1 on fail.
int exec(char *file_name)
{
	struct thread *cur = thread_current();
	check_address(file_name);

	// 문제점) SYS_EXEC - process_exec의 process_cleanup 때문에 f->R.rdi 날아감.
	// 여기서 file_name 동적할당해서 복사한 뒤, 그걸 넘겨주기
	int siz = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL)
		exit(-1);
	strlcpy(fn_copy, file_name, siz);

	if (process_exec(fn_copy) == -1)
		return -1;

	// Not reachable
	NOT_REACHED();
	return 0;
}