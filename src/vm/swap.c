#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

/* The swap slots */
struct block *swap;
/* The bitmap represents the usage of the swap */
struct bitmap *swap_table;
/* Lock used to coordinate swap */
struct lock swap_lock;

/* Note: PGSIZE = 4096, BLOCK_SECTOR_SIZE = 512
 * So each page needs 8 swap sectors.
 */
int NUM = PGSIZE / BLOCK_SECTOR_SIZE;

void
init_swap(void)
{
  swap = block_get_role(BLOCK_SWAP);
  // Number of sectors in BLOCK_SWAP
  int size = block_size(swap);
  swap_table = bitmap_create(size / NUM);
  lock_init(&swap_lock);
}

/* Save a page with the given address in swap */
block_sector_t
set_swap(void * addr)
{
  lock_acquire(&swap_lock);
  // Find a free sector in the swap table
  block_sector_t sector = bitmap_scan (swap_table, 0, 1, false);
  //printf("Found sector %d to write page %p", sector, addr);
  if(sector == BITMAP_ERROR)
    PANIC("Swap table is full.");

  int i;
  // Write page to swap
  for (i = 0; i< NUM; i++) {
    /* Write block to swap */
    block_write (swap, sector * NUM + i, addr + BLOCK_SECTOR_SIZE * i);
  }

  // Set the index in the swap table to true
  bitmap_set (swap_table, sector, true);
  lock_release(&swap_lock);
  return sector;
}

/* Get a page from the swap table */
void
get_swap(block_sector_t sector, void * addr)
{
  int i;
  for (i = 0; i< NUM; i++)
    block_read (swap, sector * NUM + i, addr + BLOCK_SECTOR_SIZE * i);

  lock_acquire(&swap_lock);
  // Deallocate the given sector in the swap table
  bitmap_set (swap_table, sector, false);
  lock_release(&swap_lock);
}

/* Mark swap sector as unused*/
void
free_sector (block_sector_t sector)
{
  lock_acquire(&swap_lock);
  // Deallocate the given sector in the swap table
  bitmap_set (swap_table, sector, false);
  lock_release(&swap_lock);
}
