#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include "devices/block.h"

void init_swap(void);
block_sector_t set_swap(void * addr);
void get_swap(block_sector_t sector, void * addr);
void free_sector (block_sector_t sector);
#endif /* vm/swap.h */
