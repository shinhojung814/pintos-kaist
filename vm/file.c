/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {
}

/* Initialize the file mapped page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page -> operations = &file_ops;

	struct file_page *file_page = &page -> file;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page -> file;

	if (page == NULL)
		return false;

	struct box *aux = (struct box *)page -> uninit.aux;
	struct file *file = aux -> file;
	off_t offset = aux -> offset;
	size_t page_read_bytes = aux -> page_read_bytes;
	size_t page_zero_bytes = PGSIZE - page_read_bytes;

	file_seek(file, offset);

	if (file_read(file, kva, page_read_bytes) != (int)page_read_bytes) 
		return false;
	
	memset(kva + page_read_bytes, 0 , page_zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
	struct file_page *file_page UNUSED = &page -> file;
	struct thread *curr = thread_current();

	if (page == NULL)
		return false;
	
	struct box *aux = (struct box *)page -> uninit.aux;

	if (pml4_is_dirty(curr -> pml4, page -> va)) {
		file_write_at(aux -> file, page -> va, aux -> page_read_bytes, aux -> offset);
		pml4_set_dirty(curr -> pml4, page -> va, false);
	}

	pml4_clear_page(curr -> pml4, page -> va);
}

/* Destory the file mapped page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
	struct file_page *file_page UNUSED = &page -> file;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
}

/* Do the munmap */
void do_munmap(void *addr) {
}