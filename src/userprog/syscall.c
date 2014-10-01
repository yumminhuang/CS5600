#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Function declarations */
void* void_value_stack (void *esp, int offset);
int* int_value_stack(void *esp, int offset);
static void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* Exit with termination message. */
void
exit_thread (int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

/* Reads the value in stack[esp + offset]
 * and checks whether it is a valid pointer.
 */
void*
void_value_stack (void *esp, int offset) {
  void *p = (void*)(esp + offset);

  if(is_user_vaddr(*(void **)p) && *(void**)p != NULL)
    return p;

  exit_thread(-1);
  return NULL;
}

int*
int_value_stack(void *esp, int offset) {
  void *p = (void*)(esp + offset);

  if(is_user_vaddr((int *)p) && (int *)p != NULL)
    return (int *)p;

  exit_thread(-1);
  return NULL;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int code = *int_value_stack(f->esp, 0);
  switch(code) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT: {
      int status = *int_value_stack(f->esp, 4);
      exit(status);
      break;
    }
    case SYS_EXEC:
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      PANIC("Wrong system call.");
  }
}

void
halt (void) {
  shutdown_power_off();
}

void
exit (int status){

}
