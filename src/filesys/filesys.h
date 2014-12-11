#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

struct file;
struct dir;

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size, bool isdir);
void filesys_open (const char *name, struct file **file, struct dir **dir, bool *isdir);
bool filesys_remove (const char *name);
bool filesys_chdir (const char* dir);

#endif /* filesys/filesys.h */
