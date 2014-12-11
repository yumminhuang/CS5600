#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "frame.h"

struct hash_iterator frames_iter;	/* Frame table iterator */	

unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool frame_hash_less_func (const struct hash_elem *a, const struct hash_elem *b,
						   void *aux UNUSED);
unsigned t_to_uaddr_hash_func (const struct hash_elem *e, void *aux UNUSED);
void clear_page_accessed (struct hash_elem *e, void *aux UNUSED);
bool t_to_uaddr_hash_less_func (const struct hash_elem *a, const struct hash_elem *b,
						   void *aux UNUSED);
void t_to_uaddr_destructor_func (struct hash_elem *e, void *aux UNUSED);
struct t_to_uaddr *t_to_uaddr_lookup (struct frame *f, struct thread *t);
typedef bool pdir_bool_func (uint32_t *pd, const void *upage);
bool ttu_ormap (struct frame *f, pdir_bool_func pdir_func);
struct frame *choose_frame(void);

/* Initializes frames for the whole user pool */
void init_frame_table (void) {
		lock_init(&exec_list_lock);
		lock_init(&frames_lock);
		cond_init(&frames_locked);
		hash_init(&frames, frame_hash_func, frame_hash_less_func, NULL);
}

/* Chooses frame to free according to clock algorithm, if all frames
   were recently used, chooses any frame that is not locked, pinned 
   or just allocated to another thread. */
struct frame *choose_frame (void) {
	
	void *start = clock_hand == ini_clock_hand ? max_clock_hand : clock_hand - PGSIZE;
	struct frame *f;
	while (start != clock_hand) {
		if (clock_hand >= max_clock_hand) {
			clock_hand = ini_clock_hand;
		}
		f = frame_lookup(clock_hand);
		if (f == NULL) {
			clock_hand = clock_hand + PGSIZE;
			continue;
		}
		if (!f->locked && !f->pinned) {
			if (is_frame_accessed (f)) {
				hash_apply(&f->thread_to_uaddr, clear_page_accessed);
				clock_hand = clock_hand + PGSIZE;
				continue;
			}
			else {
				return f;
			}
		} 
		else {
			if (is_frame_accessed (f)) {
				hash_apply(&f->thread_to_uaddr, clear_page_accessed);
			}
			clock_hand = clock_hand + PGSIZE;
			continue;
		}
	}
	f = NULL;
	while (f == NULL) {
		hash_first(&frames_iter, &frames);
		while (hash_next (&frames_iter)) {
			  f = hash_entry (hash_cur(&frames_iter), struct frame, elem);
			  if (!f->pinned && !f->locked) {
				return f;
			}
		}
		/* All frames are locked or pinned so far, wait to unlock */
		cond_wait(&frames_locked, &frames_lock);
	}
	
}

/* Allocates one frame from user pool. If no free frames left - chooses
   frame to evict page from, evicts. Marks frame as locked, if lock is set to true.
   Returns kernel virtual address, if free frame found and eviction was successful,
   panicks kernel otherwise.*/
void *allocate_frame (enum palloc_flags flags, bool lock) {
	
	lock_acquire(&frames_lock);
	void *addr = palloc_get_page (flags | PAL_USER);
	
	/*There are free frames in the user pool */
	if (addr != NULL) {

		struct frame *f = malloc (sizeof (struct frame));
		f->k_addr = addr;
		f->pinned = true;
		f->locked = lock;
		hash_init(&f->thread_to_uaddr, t_to_uaddr_hash_func, t_to_uaddr_hash_less_func, NULL);
		hash_insert(&frames, &f->elem);
	}
	else {
		/* Some of the used frames should be freed */
		struct frame *f = choose_frame();
		f->locked = lock;
		f->pinned = true;		
		addr = f->k_addr;
		struct t_to_uaddr *ttu;
		struct hash *ttus = &f->thread_to_uaddr;
		hash_first(&f->ttu_i, ttus);
		while (hash_next (&f->ttu_i))
        {
          ttu = hash_entry (hash_cur (&f->ttu_i), struct t_to_uaddr, elem);	
		  struct page *p = page_lookup(ttu->uaddr, ttu->t);
		  /* Invalidate to eliminate reads\writes */
		  p->loaded = false;
		  pagedir_clear_page (ttu->t->pagedir, p->addr);
		  switch (p->type) {
			   case MMAP: {
				  evict_mmap_page (p);
				  break;
			  }
			  case SEGMENT: {
				  if (p->writable) {
					  /* Segment that is once dirty, is always dirty */
					  if (!p->segment_dirty) { 
						bool dirty = is_frame_dirty(f);
						if (dirty) { 
						  p->segment_dirty = dirty;
						}
					  }
					  if (p->segment_dirty) { 
						  swap_in(p);
					  }
				  }
				  break;
			  }
			  case STACK: {
				  swap_in(p);
				  break;
				}
			  default: NOT_REACHED ();	
			}
		}
		hash_clear(&f->thread_to_uaddr, t_to_uaddr_destructor_func);
	
	} 
	lock_release(&frames_lock);
	return addr;	
}

/* Maps given user virtual address of the current thread to the
   frame at the given kernel virtual address */
void assign_page_to_frame (void *kaddr, void *uaddr) {
	lock_acquire(&frames_lock);
	struct frame *f = frame_lookup (kaddr);
	struct t_to_uaddr *ttu = malloc(sizeof (struct t_to_uaddr));
	ttu->t = thread_current();
	ttu->uaddr = uaddr;
	hash_insert (&f->thread_to_uaddr, &ttu->elem);
	f->pinned = false;
	cond_signal(&frames_locked, &frames_lock);
	lock_release(&frames_lock);
}

/* If no other threads are using the frame,
   deletes entry from frame table and frees frame and user pool
   address. */
void free_uninstalled_frame (void *addr) {
	lock_acquire(&frames_lock);
	struct frame *f = frame_lookup(addr);
	if (hash_empty (&f->thread_to_uaddr)) {
		palloc_free_page(addr);
		hash_delete(&frames, &f->elem);
		free(f);
	}
	f->pinned = false;
	lock_release(&frames_lock);
}

/* If no other threads are using the frame, deletes entry from frame table
   and frees frame and user pool address. */
void free_frame (struct page *p, bool freepdir) {
	p->loaded = false;
	struct frame *f = frame_lookup(p->kaddr);
	if (f != NULL) {
		struct t_to_uaddr *ttu = t_to_uaddr_lookup (f, thread_current());
		if (ttu != NULL) {
			/* Page installed */
			hash_delete(&f->thread_to_uaddr, &ttu->elem);
			if (f->pinned || !hash_empty (&f->thread_to_uaddr)) {	
			    /* Frame is shared - invalidate */
			    pagedir_clear_page(thread_current()->pagedir, ttu->uaddr);
			    free(ttu);
			}
			else {
				/* Frame used by this page only - free */
				if (freepdir) {
					pagedir_clear_page(thread_current()->pagedir, ttu->uaddr);
					palloc_free_page(p->kaddr);
				}
				hash_delete(&frames, &f->elem);
				hash_destroy(&f->thread_to_uaddr, t_to_uaddr_destructor_func);
				free(f);
			}
		}
	}

}

/* Returns true if PTE_A flag is set for any of the
   page table entries for this frame */
bool is_frame_accessed (struct frame *f) {
	return ttu_ormap (f, &pagedir_is_accessed);
}

/* Returns true if PTE_D flag is set for any of the
   page table entries for this frame */
bool is_frame_dirty (struct frame *f) {
	return ttu_ormap (f, &pagedir_is_dirty);
}

/* Returns the frame at the given kernel virtual address,
   or a null pointer if no such frame exists. */
struct frame *frame_lookup (void *address)
{
  struct frame f;
  struct hash_elem *e;
 
  f.k_addr = address;
  e = hash_find (&frames, &f.elem);
  return e != NULL ? hash_entry (e, struct frame, elem) : NULL;
}

/* Returns hash of the frame. */
unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED) {
	struct frame *f = hash_entry(e, struct frame, elem);
	return (uintptr_t)f->k_addr;
}

/* Returns true if virtual kernel address of frame a is 
   less than virtual kernel address of frame b. */
bool frame_hash_less_func (const struct hash_elem *a, const struct hash_elem *b,
						   void *aux UNUSED) {
	struct frame *f_a = hash_entry (a, struct frame, elem);
	struct frame *f_b = hash_entry (b, struct frame, elem);
	return (uintptr_t)f_a->k_addr < (uintptr_t)f_b->k_addr;
}


/* Returns hash of the frame. */
unsigned t_to_uaddr_hash_func (const struct hash_elem *e, void *aux UNUSED) {
	struct t_to_uaddr *ttu = hash_entry(e, struct t_to_uaddr, elem);
	return hash_bytes(ttu->t, sizeof ttu->t);
}

/* Returns true if address of frame a is less than address of frame b. */
bool t_to_uaddr_hash_less_func (const struct hash_elem *a, const struct hash_elem *b,
						   void *aux UNUSED) {
	struct t_to_uaddr *ttu_a = hash_entry (a, struct t_to_uaddr, elem);
	struct t_to_uaddr *ttu_b = hash_entry (b, struct t_to_uaddr, elem);
	return ttu_a->t < ttu_b->t;
}

/* Frees memory allocated to a frame */
void t_to_uaddr_destructor_func (struct hash_elem *e, void *aux UNUSED) {
	struct t_to_uaddr *ttu = hash_entry (e, struct t_to_uaddr, elem);
	free(ttu);
}

void clear_page_accessed (struct hash_elem *e, void *aux UNUSED) {
	struct t_to_uaddr *ttu = hash_entry (e, struct t_to_uaddr, elem);
	pagedir_set_accessed(ttu->t->pagedir, ttu->uaddr, false);
}

/* Returns the thread to uddr mapping,
   or a null pointer if no such mapping exists. */
struct t_to_uaddr *t_to_uaddr_lookup (struct frame *f, struct thread *t)
{
  struct t_to_uaddr ttu;
  struct hash_elem *e;
  
  ttu.t = t;
  e = hash_find (&f->thread_to_uaddr, &ttu.elem);
  return e != NULL ? hash_entry (e, struct t_to_uaddr, elem) : NULL;
}

/* Returns true if after applying function to hash table entries
   at least one returns true, false - otherwise */
bool ttu_ormap (struct frame *f, pdir_bool_func pdir_func) {

		hash_first(&f->ttu_i_b, &f->thread_to_uaddr);

		while (hash_next (&f->ttu_i_b))
        {
          struct t_to_uaddr *ttu = hash_entry (hash_cur (&f->ttu_i_b), struct t_to_uaddr, elem);
          if (pdir_func(ttu->t->pagedir, ttu->uaddr))
			  return true;
        }
		return false;
}


