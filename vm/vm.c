// /* vm.c: Generic interface for virtual memory objects. */

// #include <string.h>
// #include "lib/kernel/hash.h"
// #include "threads/malloc.h"
// #include "threads/mmu.h"
// #include "threads/vaddr.h"
// #include "vm/inspect.h"
// #include "vm/vm.h"
// #include "intrinsic.h"

// static struct lock spt_kill_lock;

// /* Initializes the virtual memory subsystem by invoking each subsystem's
//  * intialize codes. */
// void vm_init(void) {
// 	vm_anon_init();
// 	vm_file_init();
// #ifdef EFILESYS  /* For project 4 */
// 	pagecache_init();
// #endif
// 	register_inspect_intr();
// 	/* DO NOT MODIFY UPPER LINES. */
//     lock_init(&spt_kill_lock);
// }

// /* Get the type of the page. This function is useful if you want to know the
//  * type of the page after it will be initialized.
//  * This function is fully implemented now. */
// enum vm_type page_get_type(struct page *page) {
// 	int type = VM_TYPE(page -> operations -> type);
// 	switch (type) {
// 		case VM_UNINIT:
// 			return VM_TYPE(page -> uninit.type);
// 		default:
// 			return type;
// 	}
// }

// /* Helpers */
// static struct frame *vm_get_victim(void);
// static bool vm_do_claim_page(struct page *page);
// static struct frame *vm_evict_frame(void);

// unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
// bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

// /* Create the pending page object with initializer. If you want to create a
//  * page, do not create it directly and make it through this function or
//  * `vm_alloc_page`. */
// bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
// 		bool writable, vm_initializer *init, void *aux) {

// 	ASSERT(VM_TYPE(type) != VM_UNINIT)

// 	struct supplemental_page_table *spt = &thread_current() -> spt;
// 	bool writable_aux = writable;

// 	/* Check wheter the upage is already occupied or not. */
// 	if (spt_find_page(spt, upage) == NULL) {
// 		/* Create the page, fetch the initialier according to the VM type,
// 		 * and then create "uninit" page struct by calling uninit_new. You
// 		 * should modify the field after calling the uninit_new. */
// 		struct page *page = malloc(sizeof(struct page));

// 		/* Insert the page into the spt. */
// 		if (VM_TYPE(type) == VM_ANON) {
// 			uninit_new(page, upage, init, type, aux, anon_initializer);
// 		}

// 		else if (VM_TYPE(type) == VM_ANON) {
// 			uninit_new(page, upage, init, type, aux, file_backed_initializer);
// 		}

// 		page -> writable = writable_aux;
// 		spt_insert_page(spt, page);
// 		return true;
// 	}
// err:
// 	return false;
// }

// /* Find VA from spt and return page. On error, return NULL. */
// struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
// 	struct page page;
// 	page.va = pg_round_down(va);

// 	struct hash_elem *e = hash_find(spt -> page_table, &page.hash_elem);

// 	if (e == NULL)
// 		return NULL;
	
// 	struct page *result = hash_entry(e, struct page, hash_elem);
	
// 	ASSERT((va < result -> va + PGSIZE) && va >= result -> va);
// 	return result;
// }

// /* Insert PAGE into spt with validation. */
// bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
// 	struct hash_elem *result = hash_insert(spt -> page_table, &page -> hash_elem);
// 	return (result == NULL) ? true : false;
// }

// void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
// 	struct hash_elem *e = hash_delete(spt -> page_table, &page -> hash_elem);

// 	if (e != NULL)
// 		vm_dealloc_page(page);
// 	return;
// }

// static void spt_destroy(struct hash_elem *e, void *aux UNUSED) {
// 	struct page *page = hash_entry(e, struct page, hash_elem);

// 	ASSERT(page != NULL);

// 	destroy(page);
// 	free(page);
// }

// /* Get the struct frame, that will be evicted. */
// static struct frame *vm_get_victim(void) {
// 	struct frame *victim = NULL;
// 	 /* The policy for eviction is up to you. */
// 	return victim;
// }

// /* Evict one page and return the corresponding frame.
//  * Return NULL on error.*/
// static struct frame *vm_evict_frame(void) {
// 	struct frame *victim UNUSED = vm_get_victim();
// 	/* Swap out the victim and return the evicted frame. */
// 	if (victim == NULL)
// 		return NULL;
	
// 	struct page *page = victim -> page;
// 	bool swap_done = swap_out(page);

// 	if (!swap_done)
// 		PANIC("Swap is full!\n");

// 	victim -> page = NULL;
// 	memset(victim -> kva, 0, PGSIZE);

// 	return victim;
// }

// /* palloc() and get frame. If there is no available page, evict the page
//  * and return it. This always return valid address. That is, if the user pool
//  * memory is full, this function evicts the frame to get the available memory
//  * space.*/
// static struct frame *vm_get_frame(void) {
// 	struct frame *frame = malloc(sizeof(struct frame));

// 	frame -> kva = palloc_get_page(PAL_USER);
// 	frame -> page = NULL;

// 	// if (frame -> kva == NULL) {
// 	// 	free(frame);
// 	// 	frame = vm_evict_frame();
// 	// }

// 	ASSERT(frame != NULL);
// 	ASSERT(frame -> page == NULL);
// 	return frame;
// }

// /* Growing the stack. */
// static void vm_stack_growth(void *addr UNUSED) {
// }

// /* Handle the fault on write_protected page */
// static bool vm_handle_wp(struct page *page UNUSED) {
// 	return false;
// }

// /* Return true on success */
// bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
// 		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
// 	struct thread *curr = thread_current();
// 	struct supplemental_page_table *spt = &curr -> spt;
	
// 	/* Validate the fault */
// 	uint64_t fault_addr = rcr2();

// 	if (is_kernel_vaddr(addr) && user)
// 		return false;
	
// 	struct page *page = spt_find_page(spt, addr);

// 	if (page == NULL)
// 		return false;
	
// 	if (write && !not_present)
// 		return vm_handle_wp(page);

// 	return vm_do_claim_page(page);
// }

// /* Free the page.
//  * DO NOT MODIFY THIS FUNCTION. */
// void vm_dealloc_page(struct page *page) {
// 	destroy(page);
// 	free(page);
// }

// /* Claim the page that allocate on VA. */
// bool vm_claim_page(void *va UNUSED) {
// 	struct page *page = spt_find_page(&thread_current() -> spt, va);

// 	if (page == NULL)
// 		return false;

// 	return vm_do_claim_page(page);
// }

// /* Claim the PAGE and set up the mmu. */
// static bool vm_do_claim_page(struct page *page) {
// 	struct frame *frame = vm_get_frame();
// 	struct thread *curr = thread_current();

// 	/* Set links */
// 	frame -> page = page;
// 	page -> frame = frame;

// 	/* Insert page table entry to map page's VA to frame's PA. */
// 	if (!pml4_set_page(curr -> pml4, page -> va, frame -> kva, page -> writable))
// 		return false;

// 	return swap_in(page, frame -> kva);
// }

// /* Initialize new supplemental page table */
// void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
// 	struct hash *page_table = malloc(sizeof(struct hash));
	
// 	hash_init(page_table, page_hash, page_less, NULL);
// 	spt -> page_table = page_table;
// }

// /* Copy supplemental page table from src to dst */
// bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
// 	struct hash_iterator i;
	
// 	hash_first(&i, src -> page_table);

// 	while (hash_next(&i)) {
// 		struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);

// 		if (page -> operations -> type == VM_UNINIT) {
// 			vm_initializer *init = page -> uninit.init;

// 			bool writable = page -> writable;
// 			int type = page -> uninit.type;

// 			if (type & VM_ANON) {
// 				struct load_info *li = malloc(sizeof(struct load_info));

// 				li -> file = file_duplicate(((struct load_info *)page -> uninit.aux) -> file);
// 				li -> page_read_bytes = ((struct load_info *)page -> uninit.aux) -> page_read_bytes;
// 				li -> page_zero_bytes = ((struct load_info *)page -> uninit.aux) -> page_zero_bytes;
// 				li -> ofs = ((struct load_info *)page -> uninit.aux) -> ofs;

// 				vm_alloc_page_with_initializer(type, page -> va, writable, init, (void *)li);
// 			}

// 			else if (type & VM_FILE) {
// 			}
// 		}

// 		else if (page_get_type(page) == VM_ANON) {
// 			if (!vm_alloc_page(page -> operations -> type, page -> va, page -> writable))
// 				return false;
			
// 			struct page *new_page = spt_find_page(&thread_current() -> spt, page -> va);

// 			if (!vm_do_claim_page(new_page))
// 				return false;
			
// 			memcpy(new_page -> frame -> kva, page -> frame -> kva, PGSIZE);
// 		}

// 		else if (page_get_type(page) == VM_FILE) {
// 		}
// 	}
	
// 	return true;
// }

// /* Free the resource hold by the supplemental page table */
// void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
// 	/* Destroy all the supplemental_page_table hold by thread and
// 	 * writeback all the modified contents to the storage. */
// 	if (spt -> page_table == NULL) {
// 		return;
// 	}

// 	lock_acquire(&spt_kill_lock);
// 	hash_destroy(spt -> page_table, spt_destroy);
// 	free(spt -> page_table);
// 	lock_release(&spt_kill_lock);
// }

// unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
// 	const struct page *p = hash_entry(p_, struct page, hash_elem);
// 	return hash_bytes(&p -> va, sizeof p -> va);
// }

// bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
// 	const struct page *a = hash_entry(a_, struct page, hash_elem);
// 	const struct page *b = hash_entry(b_, struct page, hash_elem);
// 	return a -> va < b -> va;
// }






/* vm.c: Generic interface for virtual memory objects. */

// #include <string.h>
// #include "lib/kernel/hash.h"
// #include "threads/malloc.h"
// #include "threads/mmu.h"
// #include "threads/vaddr.h"
// #include "vm/anon.h"
// #include "vm/file.h"
// #include "vm/vm.h"
// #include "vm/inspect.h"
// #include "userprog/process.h"
// #include "intrinsic.h"

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "vm/anon.h"
#include "vm/file.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

static struct list frame_table;
static struct list_elem *start;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS
	pagecache_init();
#endif
	register_inspect_intr();
	list_init(&frame_table);
	start = list_begin(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
	int type = VM_TYPE (page -> operations -> type);
	switch (type) {
		case VM_UNINIT:
			return VM_TYPE (page -> uninit.type);
		default:
			return type;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);


static struct list_elem *list_next_cycle (struct list *lst, struct list_elem *elem);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`.*/
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux) {
	ASSERT(VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current() -> spt;

	/* Check whether the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. You
		 * should modify the field after calling the uninit_new. */

		/* Insert the page into the spt. */
		struct page* page = (struct page *)malloc(sizeof(struct page));
		typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
		initializerFunc initializer = NULL;
		
		switch(VM_TYPE(type)) {
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}
		uninit_new(page, upage, init, type, aux, initializer);

		page -> writable = writable;
		return spt_insert_page(spt, page);
	}

err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = (struct page *)malloc(sizeof(struct page));
	page -> va = pg_round_down(va);

	struct hash_elem *e = hash_find(&spt -> page_table, &page -> hash_elem);

	free(page);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	return insert_page(&spt -> page_table, page);
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page(page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
	struct frame *victim = NULL;
	struct thread *curr = thread_current();
	struct list_elem *e = start;

	for (start = e; start != list_end(&frame_table); start = list_next(start)) {
		victim = list_entry(start, struct frame, frame_elem);

		if (pml4_is_accessed(curr -> pml4,  victim -> page -> va))
			pml4_set_accessed(curr -> pml4, victim -> page -> va, 0);
		
		else
			return victim;
	}

	for (start = list_begin(&frame_table); start != e; start = list_next(start)) {
		victim = list_entry(start, struct frame, frame_elem);

		if (pml4_is_accessed(curr -> pml4, victim -> page -> va))
			pml4_set_accessed(curr -> pml4, victim -> page -> va, 0);
		
		else
			return victim;
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame (void) {
	struct frame *victim = vm_get_victim();
	
	swap_out(victim -> page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
	struct frame * frame = (struct frame *)malloc(sizeof(struct frame));

	frame -> kva = palloc_get_page(PAL_USER);
	
	if (frame -> kva == NULL) {
		frame = vm_evict_frame();
		frame -> page = NULL;
		return frame;
	}

	list_push_back(&frame_table, &frame -> frame_elem);
	frame -> page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame -> page == NULL);
	return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
	if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, 1)) {
		vm_claim_page(addr);
		thread_current() -> stack_bottom -= PGSIZE;
	}
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
	return false;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr,
		bool user, bool write UNUSED, bool not_present) {
	struct supplemental_page_table *spt = &thread_current() -> spt;

	/* Validate the fault */
	if (is_kernel_vaddr(addr))
		return false;

	void *rsp_stack = is_kernel_vaddr(f -> rsp) ? thread_current() -> rsp_stack : f -> rsp;

	if (not_present) {
		if (!vm_claim_page(addr)) {
			if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK) {
				vm_stack_growth(thread_current() -> stack_bottom - PGSIZE);
				return true;
			}
			return false;
		}
		
		else
			return true;
	}
	return false;
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
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame -> page = page;
	page -> frame = frame;

	/* Insert page table entry to map page's VA to frame's PA. */
	if (install_page(page -> va, frame -> kva, page -> writable))
		return swap_in(page, frame -> kva);
	
	return false;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt -> page_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;

	hash_first(&i, &src -> page_table);

	while (hash_next(&i)) {
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);

		enum vm_type type = page_get_type(parent_page);
		void *upage = parent_page -> va;
		bool writable = parent_page -> writable;
		vm_initializer *init = parent_page -> uninit.init;
		void *aux = parent_page-> uninit.aux;

		if (parent_page -> uninit.type & VM_MARKER_0)
			setup_stack(&thread_current() -> tf);
		
		else if (parent_page -> operations -> type == VM_UNINIT) {
			if (!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
				return false;
		}

		else {
			if (!vm_alloc_page(type, upage, writable))
				return false;
			
			if (!vm_claim_page(upage))
				return false;
		}

		if (parent_page -> operations -> type == VM_UNINIT) {
			struct page *child_page = spt_find_page(dst, upage);
			memcpy(child_page -> frame -> kva, parent_page -> frame -> kva, PGSIZE);
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
	/* Destroy all the supplemental_page_table hold by thread and
	 * writeback all the modified contents to the storage. */
	struct hash_iterator i;

	hash_first(&i, &spt -> page_table);

	while (hash_next(&i)) {
		struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);

		if (page -> operations -> type == VM_FILE) {
			// do_munmap(page -> va);
		}
		
		hash_destroy(&spt -> page_table, spt_destroy);
	}
}

void spt_destroy(struct hash_elem *e, void *aux UNUSED) {
	const struct page *p = hash_entry(e, struct page, hash_elem);
	free(p);
}

bool insert_page(struct hash *page_table, struct page *p) {
	if (!hash_insert(page_table, &p -> hash_elem))
		return true;
	
	else
		return false;
}

bool delete_page(struct hash *page_table, struct page *p) {
	if (!hash_delete(page_table, &p -> hash_elem))
		return true;
	
	else
		return false;
}

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes(&p -> va, sizeof p -> va);
}

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry(a_, struct page, hash_elem);
  const struct page *b = hash_entry(b_, struct page, hash_elem);

  return a -> va < b -> va;
}