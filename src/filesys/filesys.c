#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/cache.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

static struct dir* path_to_dir (const char* path);
static char* path_to_name (const char* path);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
  write_all_cache (/*Exiting */ true);
}

/* Creates an entry named NAME with the given INITIAL_SIZE.
   The entry is a directory if ISDIR is true. Otherwise
   the entry is a file.
   Returns true if successful, false otherwise.
   Fails if an entry named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir)
{
  if (strlen (name) == 0) return false;
  block_sector_t inode_sector = 0;

  struct dir *mydir = path_to_dir (name);
  char *myname = path_to_name (name);
  bool success = false;

  if (strcmp (myname, "") == 0) goto done;

  success = (mydir != NULL
             && free_map_allocate (1, &inode_sector)
             && inode_create (inode_sector, initial_size)
             && dir_add (mydir, myname, inode_sector, isdir));

  struct inode *ninode = NULL;
  struct dir *ndir = NULL;
  bool success1 = true;

  /* Add two entries "." and ".." to the created directory */
  if (success && isdir)
    success1 = ((ninode = inode_open (inode_sector))
	            && (ndir = dir_open (ninode))
				&& dir_add (ndir, ".", inode_sector, true)
				&& dir_add (ndir, "..",
				            inode_get_inumber (dir_get_inode (mydir)), true));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  if (success && (!success1)) {
    printf("fail to add . and .. when create dir name: %s\n", name);
	dir_remove (mydir, myname);
	success = false;
  }
  done:
  dir_close (mydir);
  free(myname);
  if (ndir) {
	  dir_close (ndir);
  } else {
    if (ninode) inode_close (ninode);
  }

  return success;
}

/* Opens the entry with the given NAME.
   If successful, sets ISDIR to indicate if the entry is a directory.
   If the entry is a file, sets FILE to the entry opened, sets DIR
   to NULL.
   If the entry is a directory, sets DIR to the entry opened, sets FILE
   to NULL.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails.
   If failed, sets FILE and DIR to NULL, sets ISDIR to false */
void
filesys_open (const char *name, struct file **file, struct dir **dir, bool *isdir)
{

  if (strlen(name) == 0) {
    if (file != NULL) *file = NULL;
	if (dir != NULL) *dir = NULL;
	if (isdir != NULL) *isdir = false;
	return;
  }

  struct dir *mydir = path_to_dir (name);
  char *myname = path_to_name (name);
  struct inode *inode = NULL;
  bool isdir_ = false;

  /* name is "/", open root */
  if (strcmp (myname, "") == 0) {
    if (file != NULL) *file = NULL;
	if (dir != NULL) *dir = mydir;
	if (isdir != NULL) *isdir = true;
	free (myname);
	return;
  }

  if (mydir != NULL)
    if (!dir_lookup (mydir, myname, &inode, &isdir_)) {
	  if (file != NULL) *file = NULL;
	  if (dir != NULL) *dir = NULL;
	  if (isdir != NULL) *isdir = false;
	  dir_close (mydir);
      free (myname);
	  return;
	}

  dir_close (mydir);
  free (myname);

  if (isdir_) {
    if (file != NULL) *file = NULL;
	ASSERT (dir != NULL);
	*dir = dir_open (inode);
	if (isdir != NULL) *isdir = true;
  } else {
    ASSERT (file != NULL);
    *file = file_open (inode);
	if (dir != NULL) *dir = NULL;
	if (isdir != NULL) *isdir = false;
  }
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  if (strlen(name) == 0) return false;
  
  struct dir* mydir = path_to_dir(name);
  char* myname = path_to_name(name);
  bool success = false;

  /* can't remove root */
  if (strcmp (myname, "") == 0) goto done;

  success = mydir != NULL && dir_remove (mydir, myname);

  done:
  dir_close (mydir);
  free(myname);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 2))
    PANIC ("root directory creation failed");
  if (!dir_add (dir_open_root (), ".", ROOT_DIR_SECTOR, true)
      || !dir_add (dir_open_root (), "..", ROOT_DIR_SECTOR, true))
	PANIC ("add entry . and .. for root directory failed");
  free_map_close ();
  printf ("done.\n");
}

/* Change current thread's work directory to DIR.
   Returns true if successful, otherwise false */
bool filesys_chdir (const char* dir)
{
  if (strlen(dir) == 0) return false;

  struct dir* mydir = path_to_dir(dir);
  char* myname = path_to_name(dir);
  struct inode* inode = NULL;
  bool isdir = false;

  bool success = false;

  /* Change work directory to root */
  if (strcmp(myname, "") == 0) {
    if (thread_current()->cwd) dir_close(thread_current()->cwd);
	thread_current()->cwd = mydir;
	success = true;
	goto done;
  }

  if (!dir_lookup(mydir, myname, &inode, &isdir)) {
    dir_close(mydir);
	success = false;
	goto done;
  }

  if (!isdir) {
    dir_close(mydir);
	success = false;
  } else {
    if (thread_current()->cwd) dir_close(thread_current()->cwd);
	thread_current()->cwd = dir_open(inode);
	dir_close(mydir);
	success = true;
  }

  done:
  free(myname);
  return success;
}

/* Traverse directory hierachy according to tokens in PATH, except
   for the last token.
   Examples:
   PATH = "", returns a struct dir* that points to current thread's work directory
   PATH = "/", returns a struct dir* that points to root
   PATH = "a", returns a struct dir* that points to current thread's work directory
   PATH = "/a", returns a struct dir* that points to root
   PATH = "/a/b", returns a struct dir* that points to directory "a"  under root
   PATH = "a/b", returns a struct dir* that points to directory "a"
   under current thread's work directory
   PATH = "/a/./../b", returns a struct dir* that points to root
   If failed, returns NULL. If successful, caller is responsible
   for closing the struct dir* */
static struct dir* path_to_dir (const char* path)
{
  struct dir* dir;
  char *s = (char *)malloc(sizeof(char) * (strlen(path) + 1));
  memcpy(s, path, strlen(path));
  s[strlen(path)] = '\0';

  /* If first char in path is '/' or if current thread's work directory
     is NULL (which means work directory is root), open root.
     Otherwise, open current thread's work directory */
  if (s[0] == '/' || !thread_current ()->cwd){
    dir = dir_open_root ();
  } else {
    dir = dir_reopen(thread_current()->cwd);
  }

  char *save_ptr;
  char *token;
  char *next_token;
  token = strtok_r(s, "/", &save_ptr);

  if (token)
    next_token = strtok_r(NULL, "/", &save_ptr);
  else
    next_token = NULL;

  if (next_token == NULL) return dir;

  struct inode *inode;
  bool isdir;
  for (; next_token != NULL; token = next_token,
       next_token = strtok_r(NULL, "/", &save_ptr)) {

	if (!dir_lookup(dir, token, &inode, &isdir)) return NULL;

	dir_close(dir);
	dir = dir_open(inode);

	if (!isdir){
	  dir_close(dir);
	  return NULL;
	}
  }

  return dir;
}

/* Returns last token in PATH
   Examples:
   PATH = "", returns ""
   PATH = "/", returns ""
   PATH = "a", returns "a"
   PATH = "/a", returns "a"
   PATH = "/a/b", returns "b"
   PATH = "a/b", returns "b"
   PATH = "/a/./../b", returns "b"
   Caller is responsible for freeing the char* */
static char* path_to_name (const char* path)
{
  if (strcmp(path, "") == 0) goto done_empty;

  char *s = (char *)malloc(sizeof(char) * (strlen(path) + 1));
  memcpy(s, path, strlen(path));
  s[strlen(path)] = '\0';

  char *save_ptr;
  char *token;
  char *next_token;
  token = strtok_r(s, "/", &save_ptr);

  if (token)
    next_token = strtok_r(NULL, "/", &save_ptr);
  else
    goto done_empty;

  if (next_token == NULL) goto done;

  for (; next_token != NULL; token = next_token,
       next_token = strtok_r(NULL, "/", &save_ptr))
    ;

  done:
  ;
  char *name = (char *)malloc(sizeof(char) * (strlen(token) + 1));
  memcpy(name, token, strlen(token));
  name[strlen(token)] = '\0';
  return name;

  done_empty:
  ;
  char *empty = (char *)malloc(sizeof(char));
  empty[0] = '\0';
  return empty;
}