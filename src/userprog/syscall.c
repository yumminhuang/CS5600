#include "userprog/syscall.h"
#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"


/* Function declarations */
static void syscall_handler (struct intr_frame *);
static int halt_handler (void);
static int exec_handler (const char *cmd_line);
static int wait_handler (pid_t pid);
static int create_handler (const char *file, unsigned initial_size);
static int remove_handler (const char *file);
static int open_handler (const char *file);
static int filesize_handler (int fd);
static int read_handler (int fd, void *buffer, unsigned size);
static int write_handler (int fd, const void *buffer, unsigned size);
static int seek_handler (int fd, unsigned position);
static int tell_handler (int fd);
static int close_handler (int fd);

static struct file * file_from_fd (struct thread * t, int fd);
static int read_from_stdin (void *buffer, unsigned size);
static int read_from_file (struct thread *t, int fd, void *buffer, unsigned size);
static int write_to_file (struct thread *t, int fd, const void *buffer, unsigned size);

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_table[128];

static struct lock lock1;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Initialize syscall table. */
  syscall_table[SYS_HALT] = (handler)halt_handler;
  syscall_table[SYS_EXIT] = (handler)exit_handler;
  syscall_table[SYS_EXEC] = (handler)exec_handler;
  syscall_table[SYS_WAIT] = (handler)wait_handler;
  syscall_table[SYS_CREATE] = (handler)create_handler;
  syscall_table[SYS_REMOVE] = (handler)remove_handler;
  syscall_table[SYS_OPEN] = (handler)open_handler;
  syscall_table[SYS_FILESIZE] = (handler)filesize_handler;
  syscall_table[SYS_READ] = (handler)read_handler;
  syscall_table[SYS_WRITE] = (handler)write_handler;
  syscall_table[SYS_SEEK] = (handler)seek_handler;
  syscall_table[SYS_TELL] = (handler)tell_handler;
  syscall_table[SYS_CLOSE] = (handler)close_handler;
  
  /* Initialize lock */
  lock_init (&lock1);
}

static void
syscall_handler (struct intr_frame *f)
{
  handler func;
  int *p, ret;

  p = f->esp;

  if (!is_user_vaddr(p))
    goto invalid;

  if (*p < SYS_HALT || *p > SYS_INUMBER)
    goto invalid;

  func = syscall_table[*p];

  if (!(is_user_vaddr(p + 1) &&
        is_user_vaddr(p + 2) &&
        is_user_vaddr(p + 3)))
    goto invalid;

  ret = func(*(p + 1), *(p + 2), *(p + 3));

  f->eax = ret;
  return;

invalid:
  exit_handler(-1);
}

/* Terminates Pintos by calling shutdown_power_off(). */
static int
halt_handler (void)
{
  shutdown_power_off ();
}

/* Terminates the currnet user program, returning status to
 * the kernal. */
int
exit_handler (int status)
{
  struct thread *t = thread_current ();
  struct list_elem *e;

  t->exit_status = status;
  
  /* close all files opened by the process */
  while (!list_empty (&t->opened_files))
  {
    e = list_begin (&t->opened_files);
	struct file_fd *f = list_entry (e, struct file_fd, elem);
	
	close_handler (f->fd);
  }
  
  thread_exit();
  return -1;
}

/* Runs the executable whose name is given in cmd_line, passing any
 * given arguments, and returns the new process's program id (pid). */
static int
exec_handler (const char * cmd_line)
{
  int ret;
  
  if(!cmd_line)
    return -1;
	
  lock_acquire (&lock1);
  ret = (int) process_execute(cmd_line);
  lock_release (&lock1);
  
  return ret;
}

/* Waits for a child process pid and retrieves the child's exit
 * status. */
static int
wait_handler (pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in
 * size. */
static int
create_handler (const char *file, unsigned initial_size)
{
  if (file == NULL)
    exit_handler (-1);
	
  return filesys_create (file, initial_size);
}

/* Deletes the file called file. */
static int
remove_handler (const char *file)
{
  if (!file)
	return 0;
  if (!is_user_vaddr (file))
	  exit_handler (-1);
  return filesys_remove (file);
}

/* Opens the file called file. */
static int
open_handler (const char *file)
{
  struct file * ret_file;
  struct file_fd * file_handle;
  struct thread * t = thread_current ();
  
  if (file == NULL)
    exit_handler (-1);
  
  ret_file = filesys_open (file);
  
  if (ret_file == NULL)
    return -1;
  
  file_handle = (struct file_fd *) malloc (sizeof (struct file_fd));
  file_handle->file = ret_file;
  file_handle->fd = t->next_fd;
  
  t->next_fd++;
  list_push_back (&t->opened_files, &file_handle->elem);
  
  return file_handle->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int
filesize_handler (int fd)
{
  struct thread *t = thread_current ();
  
  struct file *file = file_from_fd (t, fd);
  
  if (file == NULL)
    return -1;
  
  return file_length (file);
}

/* Reads size bytes from the file open as fd into buffer. Returns
 * the number of bytes actually read (0 at end of file), or -1 if
 * the file could not be read (due to a condition other than end of
 * file). Fd 0 reads from the keyboard using input_getc(). */
static int
read_handler (int fd, void *buffer, unsigned size)
{
  int ret = -1;
  
  if ((!is_user_vaddr (buffer)) || ((!is_user_vaddr (buffer + size))))  /* if buffer is a bad pointer */
    exit_handler (-1);
  
  switch (fd)
  {
    case 1:  /* read from STDOUT should return -1 */
	  break;
	  
	case 0:  /* read from keyboard */
	  lock_acquire (&lock1);
	  ret = read_from_stdin (buffer, size);
	  lock_release (&lock1);
	  break;
	  
	default: /* read from file */
	  lock_acquire (&lock1);
	  ret = read_from_file (thread_current (), fd, buffer, size);
      lock_release (&lock1);
  }
  
  return ret;
}

/* Writes size bytes from buffer to the open file fd. Returns the
 * number of bytes actually written, which may be less than size if
 * some bytes could not be written. */
static int
write_handler (int fd, const void *buffer, unsigned size)
{
  int ret = -1;
  
  if ((!is_user_vaddr (buffer)) || ((!is_user_vaddr (buffer + size))))  /* if buffer is a bad pointer */
	exit_handler (-1);
  
  switch (fd)
  {
    case 0:  /* write to STDIN should return -1 */
	  break;
	case 1:  /* write to console */
	  putbuf(buffer, size);
	  ret = size;
	  break;
	  
	default: /* write to file */
	  lock_acquire (&lock1);
	  ret = write_to_file (thread_current (), fd, buffer, size);
      lock_release (&lock1);	
  }

  return ret;
}

/* Changes the next byte to be read or written in open file fd to
 * position, expressed in bytes from the beginning of the file.
 * (Thus, a position of 0 is the file's start.) */
static int
seek_handler (int fd, unsigned position)
{
  struct file * f;
  
  f = file_from_fd (thread_current (), fd);
  if (f == NULL)
    return -1;
  
  file_seek (f, (off_t) position);
  
  return 0;
}

/* Returns the position of the next byte to be read or written in
 * open file fd, expressed in bytes from the beginning of the file. */
static int
tell_handler (int fd)
{
  struct file * f;
  
  f = file_from_fd (thread_current (), fd);
  if (f == NULL)
    return -1;  
  
  return (int) file_tell (f);
}

/* Closes file descriptor fd. Exiting or terminating a process
 * implicitly closes all its open file descriptors, as if by calling
 * this function for each one. */
static int
close_handler (int fd)
{
  struct list_elem *e;
  struct thread *t;
  int ret = -1;
  
  t = thread_current ();

  for (e = list_begin (&t->opened_files); 
       e != list_end (&t->opened_files);
       e = list_next (e))
    {
      struct file_fd *f = list_entry (e, struct file_fd, elem);	  
      if (f->fd == fd)
	  {
	    file_close (f->file);
	    list_remove (&f->elem);
		free(f);
		
		ret = 0;
		break;
	  }
    }
	
	return ret;
}

/* Helper Functions */

/* GIVEN a thread and a file descriptor
 * RETURNS a struct file * that corresponds to the 
 * file descriptor of the thread 
 * or NULL if cannot find the file */
static struct file *
file_from_fd (struct thread *t, int fd)
{
  struct list_elem *e;
  struct file *ret = NULL;

  for (e = list_begin (&t->opened_files); 
       e != list_end (&t->opened_files);
       e = list_next (e))
    {
      struct file_fd *f = list_entry (e, struct file_fd, elem);	  
      if (f->fd == fd)
	  {
	    ret = f->file;
		break;
	  }
    }
  
  return ret;
}

static int
read_from_stdin (void *buffer, unsigned size)
{
  int i;
  
  for (i = 0; i < (int) size; i++)
    * (uint8_t *) (buffer + i) = input_getc ();
	
  return size;
}

static int
read_from_file (struct thread *t, int fd, void *buffer, unsigned size)
{
  struct file * f;
  
  f = file_from_fd (t, fd);
  if (f == NULL)
    return -1;
  
  return file_read (f, buffer, (off_t) size);
}

static int
write_to_file (struct thread *t, int fd, const void *buffer, unsigned size)
{
  struct file * f;
  
  f = file_from_fd (t, fd);
  if (f == NULL)
    return -1;
  
  return file_write (f, buffer, (off_t) size);
}
