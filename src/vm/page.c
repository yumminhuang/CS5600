#include "vm/page.h"
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/inode.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

static bool
load_page_from_file (uint8_t *f, struct file *file, off_t ofs,
                     uint32_t page_read_bytes, uint32_t page_zero_bytes);
static bool try_loading_shared (struct page *p, bool lock);
unsigned exec_threads_hash (const struct hash_elem *e_, void *aux UNUSED);
bool
exec_threads_less (const struct hash_elem *a_, const struct hash_elem *b_,
                   void *aux UNUSED);
/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  //return hash_bytes (&p->addr, sizeof p->addr);
  return (unsigned) p->addr;
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->addr < b->addr;
}

/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
struct page *
page_lookup (const void *address, struct thread *t)
{
  struct page p;
  struct hash_elem *e;

  // Get page's address
  p.addr = pg_round_down (address);
  e = hash_find (&t->page_table, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Add a page to the supplemental page table */
void
add_page_stack (void * addr, bool writable, void * kaddr)
{
  struct page * p = (struct page *) malloc (sizeof(struct page));
  p->addr = addr;
  p->writable = writable;
  p->type = STACK;
  p->kaddr = kaddr;
  p->fd = -1;
  p->loaded = true;
  p->swapped = false;
  hash_insert(&thread_current()->page_table, &p->hash_elem);
}

void
add_page_segment (void * addr, bool writable, off_t ofs,
                  uint32_t read_bytes, uint32_t zero_bytes)
{
  struct page * p = (struct page *) malloc (sizeof(struct page));
  p->addr = addr;
  p->writable = writable;
  p->type = SEGMENT;
  p->offset = ofs;
  p->read_bytes = read_bytes;
  p->zero_bytes = zero_bytes;
  p->loaded = false;
  p->swapped = false;
  hash_insert(&thread_current()->page_table, &p->hash_elem);
}

void
add_page_mmap (void * addr, off_t ofs, struct file *file,
               uint32_t read_bytes, uint32_t zero_bytes) {
    struct page * p = (struct page *) malloc (sizeof(struct page));
    p->addr = addr;
    p->writable = true;
    p->type = MMAP;
    p->offset = ofs;
    p->file = file;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->loaded = false;
    hash_insert(&thread_current()->page_table, &p->hash_elem);
}

/* Obtain a frame to store the page, Fetch the data into the frame
   Point the page table entry for the virtual address to the
   physical page */
bool
load_page (struct page *p, bool lock)
{
  void *kaddr = NULL;

  if (!p->writable && try_loading_shared (p, lock)) {
  return true;
  }

  enum palloc_flags flags = PAL_ZERO;
  kaddr = allocate_frame (flags, lock);

  if (!kaddr)
    return false;

  switch (p->type) {
    case SEGMENT: {

      if (p->swapped) {
        swap_out(p, kaddr);
      }
      else {
        if(!load_page_from_file (kaddr, thread_current()->exec,
            p->offset, p->read_bytes, p->zero_bytes))
        return false;
      }
      break;
    }
    case MMAP: {
      if(!load_page_from_file (kaddr, p->file, p->offset,
                    p->read_bytes, p->zero_bytes)){
        return false;
      }
      break;
    }
    case STACK: {
      return grow_stack(p->addr, false, kaddr);
    }

    default: NOT_REACHED ();
  }

  if (!install_page (p->addr, kaddr, p->writable)){
    free_uninstalled_frame (kaddr);
    return false;
  }
  p->kaddr = kaddr;
  p->loaded = true;
  return true;
}

bool
grow_stack (void * addr, bool lock, void *kaddr)
{
  void *frame;
  if (kaddr == NULL) {
    enum palloc_flags flags = PAL_ZERO;
    frame = allocate_frame (flags, lock);
    if (!frame)
      return false;
  }
  else {
    frame = kaddr;
  }

  void *paddr = pg_round_down (addr);
  struct page *p = page_lookup (paddr, thread_current ());

  if (p != NULL && p->swapped) {
    swap_out(p, frame);
  }
  else {
    add_page_stack (paddr, true, frame);
    p = page_lookup (paddr, thread_current ());
  }

  if (!install_page (p->addr, frame, p->writable)){
    free_uninstalled_frame (frame);
    hash_delete (&thread_current()->page_table, &p->hash_elem);
    free (p);
    return false;
  }
  p->loaded = true;
  return true;
}

/* Reads page_read_bytes from the given file, starting at the given offset
   ofs to the given frame f, and zeroes the rest of the frame with number
   of page_zero_bytes. */
static bool
load_page_from_file (uint8_t *kaddr, struct file *file, off_t ofs,
                     uint32_t page_read_bytes, uint32_t page_zero_bytes)
{
  ASSERT ((page_read_bytes + page_zero_bytes) % PGSIZE == 0);

  lock_acquire(&filesyslock);
  file_seek (file, ofs);
  int f_read_bytes = file_read (file, kaddr, page_read_bytes);
  lock_release(&filesyslock);

  if (f_read_bytes != (int) page_read_bytes)
  {
    free_uninstalled_frame(kaddr);
    return false;
  }
  memset (kaddr + page_read_bytes, 0, page_zero_bytes);
  return true;
}

/* if page is written, write back to file.
 * free frame, set loaded to false */
void
release_mmap_page (struct page *p) {
  if (!p->loaded)
    return;
  void *kaddr = p->kaddr;
  struct frame *f = frame_lookup (kaddr);
  ASSERT (f != NULL);
  bool dirty = is_frame_dirty (f);

  if (!dirty) {
  lock_acquire(&frames_lock);
    free_frame (p, true);
  lock_release(&frames_lock);
    return;
  }

  /* Pin the frame */
  lock_acquire(&frames_lock);
  f->pinned = true;
  lock_release(&frames_lock);

  lock_acquire (&filesyslock);
  uint32_t f_write_bytes = file_write_at (p->file, kaddr, p->read_bytes, p->offset);
  ASSERT (f_write_bytes == p->read_bytes);
  lock_release (&filesyslock);

  /* Writing done, unpin the frame */
  lock_acquire(&frames_lock);
  f->pinned = false;
  free_frame (p, true);
  lock_release(&frames_lock);
}

/* If MMAP page is dirty, write back to file, return - otherwise. */
void
evict_mmap_page (struct page *p) {

  void *kaddr = p->kaddr;

  struct frame *f = frame_lookup (kaddr);
  ASSERT (f != NULL);
  bool dirty = is_frame_dirty (f);
  if (!dirty)
    return;

  lock_acquire (&filesyslock);
  uint32_t f_write_bytes = file_write_at (p->file, kaddr, p->read_bytes, p->offset);
  ASSERT (f_write_bytes == p->read_bytes);
  lock_release (&filesyslock);
}


/* Frees memory allocated for a page in a supplementary table.
   If page is of SWAP type, also updates swap bitmap. */
void
page_destructor (struct hash_elem *p_, void *aux UNUSED)
{
  lock_acquire(&frames_lock);
  struct page *p = hash_entry (p_, struct page, hash_elem);
  switch (p->type){
      case MMAP: {
        /* Mappings are freed on exit */
        free(p);
        break;
      }
      case SEGMENT:{
        if (!p->swapped) {
            free_frame (p, false);
            free (p);
        }
        else {
            free_sector (p->sector);
            free (p);
        }
        break;
    }
      case STACK: {
        if (!p->swapped) {
            free_frame (p, false);
            free (p);
        }
        else {
            free_sector (p->sector);
            free (p);
        }

        break;
    }
      default: NOT_REACHED ();
    }
  lock_release(&frames_lock);
}

/* Swap a page from frame to swap slots */
void
swap_in (struct page *p)
{
    p->sector = set_swap(p->kaddr);
    p->swapped = true;
    p->loaded = false;
}

/* Load frame from swap slots */
void
swap_out(struct page *p, void *k_addr)
{
    get_swap(p->sector, k_addr);
    p->kaddr = k_addr;
    p->swapped = false;
}

/* Returns a hash value for exec_threads e_. */
unsigned
exec_threads_hash (const struct hash_elem *e_, void *aux UNUSED)
{
  struct exec_threads *e = hash_entry (e_, struct exec_threads,
                                             hash_elem);
  return hash_string (e->exec_name);
}

/* Returns true if exec_threads a precedes exec_threads b. */
bool
exec_threads_less (const struct hash_elem *a_, const struct hash_elem *b_,
                   void *aux UNUSED)
{
  const struct exec_threads *a = hash_entry (a_, struct exec_threads,
                                             hash_elem);
  const struct exec_threads *b = hash_entry (b_, struct exec_threads,
                                             hash_elem);
  return hash_string (a->exec_name) <  hash_string (b->exec_name);
}

/* Returns the exec_threads entry containing the given executable file,
   or a null pointer if no such executable file exists. */
struct
exec_threads * exec_threads_lookup (char *exec_name)
{
  struct exec_threads et;
  struct hash_elem *e;

  strlcpy (et.exec_name, exec_name, sizeof (et.exec_name));
  e = hash_find (&exec_threads_table, &et.hash_elem);
  return e != NULL ? hash_entry (e, struct exec_threads, hash_elem) : NULL;
}

/* If exec is in exec_threads_table, append the thread to the list,
 * Otherwise, insert a new entry for exec.
 */
void
add_exec_threads_entry(struct thread *t)
{
  struct exec_threads *et = exec_threads_lookup(t->name);

  if (et) {
    list_push_back (&et->threads, &t->exec_elem);
  } else {
    struct exec_threads *et = malloc(sizeof (struct exec_threads));
    strlcpy (et->exec_name, t->name, sizeof (et->exec_name));
    list_init(&et->threads);
    list_push_back (&et->threads, &t->exec_elem);
    hash_insert (&exec_threads_table, &et->hash_elem);
  }
}

/* Remove entry from exec_threads_table when evict or exit
 */
void
remove_exec_threads_entry (struct thread *t)
{
  struct list_elem *e;
  struct exec_threads *et = exec_threads_lookup (t->name);

  if (et) {
    if (list_size (&et->threads) == 1) {
      /* Threads list has only one element, delete the entry from
       * exec_threads_table
       */
      hash_delete(&exec_threads_table, &et->hash_elem);
    free (et);
  }
    else {
      /* Remove the thread from threads list */
      for (e = list_begin (&et->threads);
           e != list_end (&et->threads);
           e = list_next (e))
        {
          struct thread *tmp = list_entry (e, struct thread, exec_elem);
          if(tmp == t) {
            list_remove(&tmp->exec_elem);
            break;
          }
        }
    }
  }
}

/* Tries to locate a shared frame that contains the data for the
   read-only segment page. Installs page, updates supplementary page table
   and frame and returns true, if such frame is found, returns false - otherwise. */
static bool try_loading_shared (struct page *p, bool lock) {

  lock_acquire(&exec_list_lock);

  struct exec_threads *et = exec_threads_lookup (thread_current()->name);
  if (et) {
    struct list_elem *e = list_begin(&et->threads);
    while (e != list_end (&et->threads)) {
      struct thread *t = list_entry (e, struct thread, exec_elem);

      /* Check page of related thread t */
      if (t == thread_current()) {
        e = list_next(e);
        continue;
      }

      lock_acquire(&frames_lock);
      struct page *same_p = page_lookup(p->addr, t);
      if (same_p->loaded) {
        struct frame *f = frame_lookup (same_p->kaddr);
        f->pinned = true;
        p->kaddr = f->k_addr;
        lock_release(&frames_lock);
        lock_release(&exec_list_lock);
        if (!install_page (p->addr, f->k_addr, p->writable)){
           free_uninstalled_frame (f->k_addr);
           return false;
        }
        p->loaded = true;
        f->locked = lock;
        return true;
      }
      lock_release(&frames_lock);
      e = list_next(e);
    }
  }

  lock_release(&exec_list_lock);
  return false;
}

