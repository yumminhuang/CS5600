#include "threads/thread.h"
#include "threads/palloc.h"
#include "page.h"
#include "hash.h"

/* Frame table entry */
struct frame
  {
	void *k_addr;					/* Kernel virtual address mapped to frame physical address */
	bool pinned;					/* Is data being read into the frame */
	bool locked;					/* Frame filled for syscall*/
	struct hash thread_to_uaddr;	/* Threads using the frame with user virtual addresses mapped to it */ 
	struct hash_iterator ttu_i;		/* Iterator over thread_to_uaddr table */
	struct hash_iterator ttu_i_b;	/* Iterator over thread_to_uaddr table - bits check*/
	struct hash_elem elem;			/* Frames hash table element */
  };
  
/* Thread to user virtual address mapping */  
struct t_to_uaddr {
	struct thread *t;				/* Pointer to a thread using the frame */
	void *uaddr;					/* User virtual address mapped to the frame in thread t */ 
	struct hash_elem elem;			/* Hash element of thread_to_uaddr */
	};
  
 
  struct hash frames;				 /* Frames table */
  struct lock frames_lock;			 /* Frame lock */
  struct condition frames_locked;	 /* Condition to wait on for any frame to unpin\unlock */
  void *clock_hand;					 /* Frame the clock algorithm currently points to */
  void *ini_clock_hand;				 /* Initial position of the clock hand */
  void *max_clock_hand;				 /* Maximum position of the clock hand (maximal address of the frames in the user pool */
  
  void *allocate_frame (enum palloc_flags flags, bool lock);
  void free_frame (struct page *p, bool freepdir);
  void free_uninstalled_frame (void *addr);
  void init_frame_table (void);
  void assign_page_to_frame (void *kaddr, void *uaddr);
  struct frame *frame_lookup (void *address);
  bool is_frame_accessed (struct frame *f);
  bool is_frame_dirty (struct frame *f);