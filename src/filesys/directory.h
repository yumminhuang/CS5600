#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

/* Size of a single dir entry */
#define DIR_ENTRY 24

struct inode;

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);
bool dir_is_root (struct dir *dir);
bool dir_is_empty (struct dir *dir);
bool dir_in_use (struct dir *dir);

/* Reading and writing. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode, bool *isdir);
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool isdir);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

#endif /* filesys/directory.h */
