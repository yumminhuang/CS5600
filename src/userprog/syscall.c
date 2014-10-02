#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static int sys_exit (int status);
static int sys_halt (void);
// static int sys_create (const char *file, unsigned initial_size);
// static int sys_open (const char *file);
// static int sys_close (int fd);
// static int sys_read (int fd, void *buffer, unsigned size);
// static int sys_write (int fd, const void *buffer, unsigned length);
static int sys_exec (const char * cmd);
static int sys_wait (pid_t pid);
// static int sys_filesize (int fd);
// static int sys_tell (int fd);
// static int sys_seek (int fd, unsigned pos);
// static int sys_remove (const char *file);

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_vec[128];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_vec[SYS_EXIT] = (handler)sys_exit;
  syscall_vec[SYS_HALT] = (handler)sys_halt;
  // syscall_vec[SYS_CREATE] = (handler)sys_create;
  // syscall_vec[SYS_OPEN] = (handler)sys_open;
  // syscall_vec[SYS_CLOSE] = (handler)sys_close;
  // syscall_vec[SYS_READ] = (handler)sys_read;
  // syscall_vec[SYS_WRITE] = (handler)sys_write;
  syscall_vec[SYS_EXEC] = (handler)sys_exec;
  syscall_vec[SYS_WAIT] = (handler)sys_wait;
  // syscall_vec[SYS_FILESIZE] = (handler)sys_filesize;
  // syscall_vec[SYS_SEEK] = (handler)sys_seek;
  // syscall_vec[SYS_TELL] = (handler)sys_tell;
  // syscall_vec[SYS_REMOVE] = (handler)sys_remove;
}

static void
syscall_handler (struct intr_frame *f)
{
  handler func;
  int *p, ret;

  p = f->esp;
  if(!is_user_vaddr(p)) {
    sys_exit(-1);
    return;
  }

  func = syscall_vec[*p];

  ret = func(*(p + 1), *(p + 2), *(p + 3));
  f->eax = ret;

  return;
}

/* Terminates Pintos by calling shutdown_power_off(). */
static int
sys_halt (void)
{
  shutdown_power_off();
}

/* Terminates the currnet user program, returning status to
 * the kernal. */
static int
sys_exit (int status)
{
  thread_current ()->exit_status = status;
  thread_exit ();
  return -1;
}

/* Runs the executable whose name is given in cmd_line, passing any
 * given arguments, and returns the new process's program id (pid). */
static int
sys_exec (const char *cmd_line)
{
  if(!cmd_line)
    return -1;
  return process_execute(cmd_line);
}

/* Waits for a child process pid and retrieves the child's exit
 * status. */
static int
sys_wait (pid_t pid)
{
  return process_wait(pid);
}
