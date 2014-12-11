#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Maximum number of blocks for each inode
   Maximum file size is 8460288 Bytes */
#define DIRECT_BLOCKS 12
#define INDIRECT_BLOCKS 1
#define DOUBLY_INDIRECT_BLOCKS 1

/* Index of blocks */
#define DIRECT_INDEX 0
#define INDIRECT_INDEX DIRECT_BLOCKS
#define DOUBLY_INDIRECT_INDEX DIRECT_BLOCKS + INDIRECT_BLOCKS

/* The number of pointers in inode */
#define INODE_BLOCK_PTRS DOUBLY_INDIRECT_INDEX + DOUBLY_INDIRECT_BLOCKS
/* The number of sector pointers in a block
 * BLOCK_SECTOR_SIZE / sizeof(block_sector_t) */
#define INDIRECT_BLOCK_PTRS 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                          /* File size in bytes. */
    unsigned magic;                        /* Magic number. */
    uint32_t direct_index;                 /* Direct block pointer index */
    uint32_t indirect_index;               /* Indirect pointer index */
    uint32_t doubly_indirect_index;        /* Doubly indirect pointer index */
    block_sector_t ptr[INODE_BLOCK_PTRS];  /* Pointers to blocks */
    uint32_t unused[109];                  /* Not used. */
  };

/* Used for indirect and doubly indirect block */
struct indirect_block
  {
    block_sector_t ptr[INDIRECT_BLOCK_PTRS];  /* Pointers to blocks */
  };

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock ilock;                  /* Lock */
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;


/* Function declaration */
bool inode_alloc(struct inode_disk *disk_inode, off_t length);
void inode_dealloc (struct inode_disk *disk_inode);
void inode_dealloc_block (block_sector_t *sector, size_t size);
size_t
inode_extend_indirect_block (struct inode_disk *i_d, size_t sectors);
size_t
inode_extend_nested_block (struct inode_disk *i_d, size_t sectors,
                           struct indirect_block *block);
size_t
inode_extend_doubly_indirect_block (struct inode_disk *i_d, size_t sectors);


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the number of indirect sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_indirect_sectors (off_t size)
{
  if (size <= BLOCK_SECTOR_SIZE * DIRECT_BLOCKS)
      return 0;
  size -= BLOCK_SECTOR_SIZE * DIRECT_BLOCKS;
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS);
}

/* Returns the number of doubly indirect sectors to allocate for an
   inode SIZE bytes long. */
static inline size_t
bytes_to_doubly_indirect_sector (off_t size)
{
  off_t bound = BLOCK_SECTOR_SIZE * (DIRECT_BLOCKS +
                                     INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS);
  return size <= bound ? 0 : DOUBLY_INDIRECT_BLOCKS;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos, off_t growed_size)
{
  ASSERT (inode != NULL);
  block_sector_t result;
  struct inode_disk *i_d = (struct inode_disk *)
                            load_inode_metadata(inode->sector);
  off_t length = growed_size != 0 ? growed_size : i_d->length;
  if (pos <= length)
  {
    uint32_t idx;
    uint32_t indirect_block[INDIRECT_BLOCK_PTRS];

    if (pos < BLOCK_SECTOR_SIZE * DIRECT_BLOCKS)
    { // Data is only located in direct blocks
      idx = pos / BLOCK_SECTOR_SIZE;
      result = i_d->ptr[idx];
    }
    else if (pos < BLOCK_SECTOR_SIZE *
                   (DIRECT_BLOCKS + INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS))
    { // Data is located in indirect blocks
      pos -= BLOCK_SECTOR_SIZE * DIRECT_BLOCKS;
      idx = pos / (BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS) + DIRECT_BLOCKS;
      read_from_cache(i_d->ptr[idx], &indirect_block, 0, BLOCK_SECTOR_SIZE);
      pos %= BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS;
      result = indirect_block[pos / BLOCK_SECTOR_SIZE];
    }
    else
    { // Data is located in doubly indirect blocks
      read_from_cache(i_d->ptr[DOUBLY_INDIRECT_INDEX], &indirect_block,
                      0, BLOCK_SECTOR_SIZE);
      pos -= BLOCK_SECTOR_SIZE *
             (DIRECT_BLOCKS + INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS);
      idx = pos / (BLOCK_SECTOR_SIZE  * INDIRECT_BLOCK_PTRS);
      read_from_cache(indirect_block[idx], &indirect_block, 0,
                      BLOCK_SECTOR_SIZE);
      pos %= BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS;
      result = indirect_block[pos / BLOCK_SECTOR_SIZE];
    }
  }
  else
    result = -1;
  release_inode_metadata(inode->sector, false);
  return result;
}

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->magic = INODE_MAGIC;
      if(length == 0 || inode_alloc(disk_inode, length)) {
        disk_inode->length = length;
        write_to_cache(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
        success = true;
      }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->ilock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL) {
    inode->open_cnt++;
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Returns INODE's open count. */
int
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          struct inode_disk *i_d = (struct inode_disk *)
                                    load_inode_metadata(inode->sector);
          inode_dealloc(i_d);
          release_inode_metadata(inode->sector, true);
          free_map_release (inode->sector, 1);
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer, off_t size, off_t offset)
{
  off_t bytes_read = 0;
  block_sector_t sector_idx = 0;
  off_t length = inode_length(inode);

  if(length <= offset)
    return bytes_read;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      sector_idx = byte_to_sector (inode, offset, 0);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      read_from_cache (sector_idx, buffer + bytes_read, sector_ofs,
                       chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

    /* Add new task for read-ahead */
  block_sector_t rae_sector_idx = byte_to_sector (inode, offset,
                                                  BLOCK_SECTOR_SIZE);
  if (rae_sector_idx < block_size(fs_device)) {
    lock_acquire(read_ahead_lock_ptr);
    struct read_ahead_entry *rae = malloc (sizeof(struct read_ahead_entry));
    rae->sector_idx = sector_idx;
    list_push_back(&read_ahead_queue, &rae->elem);
    cond_signal(read_ahead_av_ptr, read_ahead_lock_ptr);
    lock_release(read_ahead_lock_ptr);
  }
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   If LOCK_ACQUIRED is true, lock in INODE has been acquired by caller.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer, off_t size,
                off_t offset, bool lock_acquired)
{
  off_t bytes_written = 0;
  block_sector_t sector_idx;
  struct inode_disk *i_d;
  bool growed = false;
  int growed_size = 0;

  if (inode->deny_write_cnt)
    return 0;

  if(offset + size > inode_length(inode)) {
    /* File growth */
    if (!lock_acquired)
      inode_acquire_lock(inode);
      i_d = (struct inode_disk *) load_inode_metadata(inode->sector);
      growed = inode_alloc(i_d, offset + size);
      growed_size = offset + size;
      if (!growed) {
		if (!lock_acquired)
			inode_release_lock(inode);
        release_inode_metadata(inode->sector, true);
        return bytes_written;
      }
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      sector_idx = byte_to_sector (inode, offset, growed_size);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = growed ? growed_size : inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      write_to_cache (sector_idx, buffer + bytes_written, sector_ofs,
                      chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  if (growed) {
	/* Update length of inode_disk after writing with growing */
	if (offset + size > i_d->length) {
		i_d->length = offset + size;
		release_inode_metadata(inode->sector, true);	
	}
    if (!lock_acquired)
      inode_release_lock(inode);
  }

  /* Add new task for read-ahead */
  if (!growed) {
    block_sector_t rae_sector_idx = byte_to_sector (inode, offset,
                                                    BLOCK_SECTOR_SIZE);
    if (rae_sector_idx < block_size(fs_device)) {
      lock_acquire(read_ahead_lock_ptr);
      struct read_ahead_entry *rae = malloc (sizeof(struct read_ahead_entry));
      rae->sector_idx = rae_sector_idx;
      list_push_back(&read_ahead_queue, &rae->elem);
      cond_signal(read_ahead_av_ptr, read_ahead_lock_ptr);
      lock_release(read_ahead_lock_ptr);
    }
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  off_t result;
  struct inode_disk *i_d = (struct inode_disk *)
                            load_inode_metadata(inode->sector);
  result = i_d->length;
  release_inode_metadata(inode->sector, false);
  return result;
}

/* Allocate indirect blocks for inode.
   Return remaining size of sectors that need to allocate */
size_t
inode_extend_indirect_block (struct inode_disk *i_d, size_t sectors)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  struct indirect_block block;

  if (i_d->indirect_index == 0)
  {
    // Allocate a new indirect block
    if (!free_map_allocate(1, &i_d->ptr[i_d->direct_index])) {
      return sectors;
    }
  }
  else
  {
    read_from_cache(i_d->ptr[i_d->direct_index], &block, 0, BLOCK_SECTOR_SIZE);
  }
  while (i_d->indirect_index < INDIRECT_BLOCK_PTRS)
  {
    if (!free_map_allocate(1, &block.ptr[i_d->indirect_index]))
      return sectors;
    write_to_cache(block.ptr[i_d->indirect_index], zeros, 0,
                   BLOCK_SECTOR_SIZE);
    i_d->indirect_index++;
    sectors--;
    if (sectors == 0)
      break;
  }
  // Update the indirect block
  write_to_cache(i_d->ptr[i_d->direct_index], &block, 0, BLOCK_SECTOR_SIZE);
  if (i_d->indirect_index == INDIRECT_BLOCK_PTRS)
  {
    // the indirect block is full
    i_d->indirect_index = 0;
    i_d->direct_index++;
  }
  return sectors;
}

size_t
inode_extend_nested_block (struct inode_disk *i_d, size_t sectors,
                           struct indirect_block *block)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  struct indirect_block nested_block;
  if (i_d->doubly_indirect_index == 0)
  {
    if (!free_map_allocate(1, &block->ptr[i_d->indirect_index]))
      return sectors;
  }
  else
  {
    read_from_cache(block->ptr[i_d->indirect_index], &nested_block, 0,
                    BLOCK_SECTOR_SIZE);
  }
  while (i_d->doubly_indirect_index < INDIRECT_BLOCK_PTRS)
  {
    if(!free_map_allocate(1, &nested_block.ptr[i_d->doubly_indirect_index]))
      return sectors;
    write_to_cache(nested_block.ptr[i_d->doubly_indirect_index],
                   zeros, 0, BLOCK_SECTOR_SIZE);
    i_d->doubly_indirect_index++;
    sectors--;
    if (sectors == 0)
      break;
  }
  write_to_cache(block->ptr[i_d->indirect_index], &nested_block, 0,
                 BLOCK_SECTOR_SIZE);
  if (i_d->doubly_indirect_index == INDIRECT_BLOCK_PTRS)
  {
    i_d->doubly_indirect_index = 0;
    i_d->indirect_index++;
  }
  return sectors;
}

size_t
inode_extend_doubly_indirect_block (struct inode_disk *i_d, size_t sectors)
{
  struct indirect_block block;
  if (i_d->indirect_index == 0 && i_d->doubly_indirect_index == 0)
  {
    free_map_allocate(1, &i_d->ptr[i_d->direct_index]);
  }
  else
  {
    read_from_cache(i_d->ptr[i_d->direct_index], &block, 0,
                    BLOCK_SECTOR_SIZE);
  }
  while (i_d->indirect_index < INDIRECT_BLOCK_PTRS)
  {
    sectors = inode_extend_nested_block(i_d, sectors, &block);
    if (sectors == 0)
      break;
  }
  write_to_cache(i_d->ptr[i_d->direct_index], &block, 0,
                 BLOCK_SECTOR_SIZE);
  return sectors;
}

/* Allocate inode_disk with size as LENGTH*/
bool
inode_alloc(struct inode_disk *i_d, off_t length)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  // Initial i_d->length is 0.
  size_t size = bytes_to_sectors(length) - bytes_to_sectors(i_d->length);

  if(size == 0)
    return true;

  /* Extend to direct blocks */
  while (i_d->direct_index < INDIRECT_INDEX)
  {
    if (!free_map_allocate (1, &i_d->ptr[i_d->direct_index])) {
      return false;
    }
    write_to_cache(i_d->ptr[i_d->direct_index], zeros, 0, BLOCK_SECTOR_SIZE);
    i_d->direct_index++;
    size--;
    if (size == 0)
      return true;
  }

  /* Extend to indirect blocks */
  while (i_d->direct_index < DOUBLY_INDIRECT_INDEX)
  {
    size = inode_extend_indirect_block(i_d, size);
    if (size == 0)
      return true;
  }

  /* Extend to doubly indirect blocks */
  if (i_d->direct_index == DOUBLY_INDIRECT_INDEX) {
    size = inode_extend_doubly_indirect_block(i_d, size);
  }
  return size == 0;
}

/* Deallocate all sectors in an indirect block*/
void
inode_dealloc_block (block_sector_t *sector, size_t size)
{
  unsigned int i;
  struct indirect_block block;
  read_from_cache(*sector, &block, 0, BLOCK_SECTOR_SIZE);
  for (i = 0; i < size; i++)
    free_map_release(block.ptr[i], 1);
  free_map_release(*sector, 1);
}

/* Deallocate inode */
void
inode_dealloc (struct inode_disk *i_d)
{
  if (i_d->length == 0)
    return;
  unsigned int idx = 0;
  size_t sectors = bytes_to_sectors(i_d->length);
  size_t i_sectors = bytes_to_indirect_sectors(i_d->length);
  size_t d_sector = bytes_to_doubly_indirect_sector(i_d->length);

  // Deallocate direct blocks
  while (sectors && idx < INDIRECT_INDEX)
  {
    free_map_release (i_d->ptr[idx], 1);
    sectors--;
    idx++;
  }
  // Deallocate indirect blocks
  while (i_sectors && idx < DOUBLY_INDIRECT_INDEX)
  {
    size_t size = sectors < INDIRECT_BLOCK_PTRS ? sectors
                                                : INDIRECT_BLOCK_PTRS;
    inode_dealloc_block(&i_d->ptr[idx], size);
    sectors -= size;
    i_sectors--;
    idx++;
  }
  // Deallocate doubly indirect blocks
  if (d_sector)
  {
    unsigned int i;
    struct indirect_block block;
    read_from_cache(i_d->ptr[idx], &block, 0, BLOCK_SECTOR_SIZE);
    for(i = 0; i < i_sectors; i++) {
      size_t size = sectors < INDIRECT_BLOCK_PTRS ? sectors
                                                  : INDIRECT_BLOCK_PTRS;
      inode_dealloc_block(&block.ptr[i], size);
      sectors -= size;
    }
    free_map_release(i_d->ptr[idx], 1);
  }
}

/* Acquire lock in inode */
void
inode_acquire_lock (struct inode *inode)
{
  lock_acquire (&inode->ilock);
}

/* Release lock in inode */
void
inode_release_lock (struct inode *inode)
{
  lock_release (&inode->ilock);
}
