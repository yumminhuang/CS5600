#include "hash.h"
#include "devices/block.h"

 /* Is cache infrastucture shut down? */
 bool cache_finish;
 /* Is cache infrastucture created? */
 bool cache_start;

 /* Entry in the buffer cache */
 struct cache_entry {
	 block_sector_t sector;			/* Sector id, which data stored in cache */
	 void *cache_addr;				/* Kernel virtual address at which data is stored */
	 bool dirty;					/* Has cache data been written to? */
	 bool accessed;					/* Has cache data been accessed? */
	 unsigned pin_count;			/* Is cached data actively in use? */
	 struct hash_elem h_elem;		/* buffer_cache hash element */
	 struct hash_elem ev_h_elem;	/* ev_buffer_cache hash element */
 };

 /* Read-ahead task queue */
 struct list read_ahead_queue;

 /* Read-ahead task */
 struct read_ahead_entry {
	 block_sector_t sector_idx;		/* Sector id to be read by read-ahead thread */
	 struct list_elem elem;			/* read_ahead_queue list element */
	 };

 /*	Pointer to read_ahead_av condition variable,
    on which read-ahead threads for tasks to be added to
	read_ahead_queue */
 struct condition *read_ahead_av_ptr;

 /* Pointer to a lock guarding changes to read_ahead_queue
    and read_ahead_av condition variable */
 struct lock *read_ahead_lock_ptr;

/* Function declarations */
void init_buffer_cache(void);
void write_all_cache(bool exiting);
void read_from_cache (block_sector_t sector_idx, void *buffer,
				  int sector_ofs, int chunk_size);
void
write_to_cache (block_sector_t sector_idx, const void *buffer, int sector_ofs,
				 int chunk_size);
void write_all_cache_thread (void);

void *load_inode_metadata (block_sector_t sector_idx);
void release_inode_metadata (block_sector_t sector_idx, bool dirty);
void set_cache_exiting (void);