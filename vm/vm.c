/* vm.c: Generic interface for virtual memory objects. */

#include <string.h>
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"
#include "vm/vm.h"
#include "intrinsic.h"

static struct list frame_list;
static struct lock clock_lock;
static struct lock spt_kill_lock;
static struct list_elem *clock_elem;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&spt_kill_lock);
	list_init(&frame_list);
	clock_elem = NULL;
	lock_init(&clock_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
	int ty = VM_TYPE(page -> operations -> type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE(page -> uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static struct frame *vm_evict_frame(void);
static bool vm_do_claim_page(struct page *page);

static uint64_t page_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current() -> spt;

	/* Check whether the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
	struct page page;

	page.va = pg_round_down(va);

	struct hash_elem *e = hash_find(spt -> page_table, &page.hash_elem);

	if (e == NULL)
		return NULL;
	
	struct page *result = hash_entry(e, struct page, hash_elem);

	ASSERT((va < result -> va + PGSIZE) && va >= result -> va);

	return result;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
	struct hash_elem *result = hash_insert(spt -> page_table, &page -> hash_elem);

	return (result == NULL) ? true : false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
	struct hash_elem *e = hash_delete(spt -> page_table, &page -> hash_elem);

	if (e != NULL)
		vm_dealloc_page(page);
	
	return true;
}

static void spt_destroy(struct hash_elem *e, void *aux UNUSED) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	
	ASSERT(page != NULL);
	
	destroy(page);
	free(page);
} 

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
	struct frame *victim = vm_get_victim();
	struct page *page = victim -> page;
	bool swap_done = swap_out(page);

	if (!swap_done)
		PANIC("Swap is full!\n");
	
	victim -> page = NULL;
	memset(victim -> kva, 0, PGSIZE);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
	struct frame *frame = malloc(sizeof(struct frame));

	frame -> kva = palloc_get_page(PAL_USER);
	frame -> page = NULL;

	if (frame -> kva == NULL) {
		free(frame);
		frame = vm_evict_frame();
	}

	ASSERT(frame -> kva != NULL);

	return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current() -> spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va) {
	struct page *page = spt_find_page(&thread_current() -> spt, va);
	
	if (page == NULL)
		return false;

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
	struct thread *curr = thread_current();
	struct frame *frame = vm_get_frame();

	/* Set links */
	ASSERT(frame != NULL);
	ASSERT(page != NULL);

	frame -> page = page;
	page -> frame = frame;

	if (clock_elem != NULL)
		list_insert(clock_elem, &frame -> elem);
	else
		list_push_back(&frame_list, &frame -> elem);

	/* Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(curr -> pml4, page -> va, frame -> kva, page -> writable))
		return false;

	return swap_in(page, frame -> kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
	struct hash * page_table = malloc(sizeof(struct hash));

	hash_init(page_table, page_hash, page_less, NULL);
	spt -> page_table = page_table;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}

static uint64_t page_hash(const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p -> va, sizeof p -> va);
}

static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a -> va < b -> va;
}