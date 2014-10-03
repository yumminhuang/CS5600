#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

/* Function declarations */
static void syscall_handler (struct intr_frame *);
static int halt_handler (void);
static int exit_handler (int status);
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

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_table[128];

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
halt_handler(void)
{
  shutdown_power_off();
}

/* Terminates the currnet user program, returning status to
 * the kernal. */
static int
exit_handler(int status)
{
  thread_current()->exit_status = status;
  thread_exit();
  return -1;
}

/* Runs the executable whose name is given in cmd_line, passing any
 * given arguments, and returns the new process's program id (pid). */
static int
exec_handler(const char * cmd_line)
{
  if(!cmd_line)
    return -1;
  return process_execute(cmd_line);
}

/* Waits for a child process pid and retrieves the child's exit
 * status. */
static int
wait_handler(pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in
 * size. */
static int
create_handler(const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}

/* Deletes the file called file. */
static int
remove_handler(const char *file)
{
  return -1;
}

/* Opens the file called file. */
static int
open_handler(const char *file)
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
static int
filesize_handler(int fd)
{
  return -1;
}

/* Reads size bytes from the file open as fd into buffer. Returns
 * the number of bytes actually read (0 at end of file), or -1 if
 * the file could not be read (due to a condition other than end of
 * file). Fd 0 reads from the keyboard using input_getc(). */
static int
read_handler(int fd, void *buffer, unsigned size)
{
  return -1;
}

/* Writes size bytes from buffer to the open file fd. Returns the
 * number of bytes actually written, which may be less than size if
 * some bytes could not be written. */
static int
write_handler(int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
    putbuf(buffer, size);
  return size;
}

/* Changes the next byte to be read or written in open file fd to
 * position, expressed in bytes from the beginning of the file.
 * (Thus, a position of 0 is the file's start.) */
static int
seek_handler(int fd, unsigned position)
{
  return -1;
}

/* Returns the position of the next byte to be read or written in
 * open file fd, expressed in bytes from the beginning of the file. */
static int
tell_handler(int fd)
{
  return -1;
}

/* Closes file descriptor fd. Exiting or terminating a process
 * implicitly closes all its open file descriptors, as if by calling
 * this function for each one. */
static int
close_handler(int fd)
{
  return -1;
}