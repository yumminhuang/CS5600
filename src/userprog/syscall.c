#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing any 
 * given arguments, and returns the new process's program id (pid). */
// pid_t 
// exec (const char *cmd_line)
// {
//   
// }

/* Waits for a child process pid and retrieves the child's exit 
 * status. */
// int 
// wait (pid_t pid)
// {
//   
// }

/* Creates a new file called file initially initial_size bytes in 
 * size. */
bool 
create (const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}

/* Deletes the file called file. */
// bool 
// remove (const char *file)
// {
//   bool filesys_remove (const char *name)  
// }

/* Opens the file called file. */
int 
open (const char *file)
{
  struct file * ret_file;
  struct file_fd * file_handle;
  struct thread * t = thread_current ();
  
  ret_file = filesys_open (file);
  
  if (ret_file == NULL)
    return -1;
  
  file_handle = (struct file_fd *) malloc (sizeof (struct file_fd));
  file_handle->f = ret_file;
  file_handle->fd = t->next_fd;
  
  t->next_fd++;
  list_push_back (&t->opened_files, &file_handle->elem);
  
  return file_handle->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
// int 
// filesize (int fd)
// {
//   
// }

/* Reads size bytes from the file open as fd into buffer. Returns 
 * the number of bytes actually read (0 at end of file), or -1 if 
 * the file could not be read (due to a condition other than end of 
 * file). Fd 0 reads from the keyboard using input_getc(). */
// int 
// read (int fd, void *buffer, unsigned size)
// {
//   
// }

/* Writes size bytes from buffer to the open file fd. Returns the 
 * number of bytes actually written, which may be less than size if 
 * some bytes could not be written. */
// int 
// write (int fd, const void *buffer, unsigned size)
// {
// 
// }

/* Changes the next byte to be read or written in open file fd to 
 * position, expressed in bytes from the beginning of the file. 
 * (Thus, a position of 0 is the file's start.) */
// void 
// seek (int fd, unsigned position)
// {
//   
// }

/* Returns the position of the next byte to be read or written in 
 * open file fd, expressed in bytes from the beginning of the file. */
// unsigned 
// tell (int fd)
// {
//   
// }

/* Closes file descriptor fd. Exiting or terminating a process 
 * implicitly closes all its open file descriptors, as if by calling 
 * this function for each one. */
// void 
// close (int fd)
// {
//   
// }