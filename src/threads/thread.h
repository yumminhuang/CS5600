#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include <stdint.h>
#include <threads/synch.h>

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING,       /* About to be destroyed. */
    THREAD_SLEEPING     /* Sleeping. */
  };

enum child_state
  {
    CHILD_LOADING,          /* Child process is loading. */
    CHILD_LOAD_FAILED,      /* Child process failed to load. */
    CHILD_LOAD_SUCCESS,     /* Child process succeded to load. */
    CHILD_EXITING           /* About to exit. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
	int64_t alarm;						/* Expected wake time, if sleeping */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    struct thread *parent;              /* Parent of this thread */
    /* Hash table for tracking status of thread's children */
    struct hash children;
    /* Hash table for tracking thread's file descriptors */
    struct hash fds;
    struct file *exec;                  /* Pointer to process executable */
	struct list_elem exec_elem;         /* List element of the executable to thread mapping. */
    unsigned short fd_cnt;              /* "Sequence" for file descriptors */
	struct hash mapids;					/* Hash table for tracking thread's mapids */
	unsigned short mapid_cnt;           /* "Sequence" for mapids */
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
#endif
    struct hash page_table;             /* Supplemental page table */
    struct dir *cwd;                    /* Pointer to current working dir */

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);
void thread_sleep (int64_t alarm);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

struct childtracker {
  tid_t child_id;                 /* Id of the child process */
  struct thread *child;           /* Pointer to the child */
  struct lock wait_lock;          /* Lock guarding child status fields */
  struct condition wait_cond;
  /* Condvar on which paent wait for child status updates */
  int exit_status;              /* Child's exit status */
  enum child_state state;       /* Child's state */
  struct hash_elem elem;        /* Hash table element */
};

struct childtracker *find_child_rec (struct thread *t, tid_t child_id);

/* Used to control max number of files allowed to opened by process */
#define MAX_FILES 126

struct fd_to_file {
  int fd;                     /* File descriptor id. */
  struct file *file_ptr;      /* Pointer to the opened file. */
  struct dir *dir_ptr;        /* Pointer to the opened directory */
  bool isdir;                 /* is directory? */
  struct hash_elem elem;      /* Hash table element. */
};

struct mapping {
  int mapid;                  /* Mapping id */
  void *addr;                 /* Virtual address of first page */
  int pnum;                   /* Number of virtual pages */
  struct hash_elem elem;      /* Hash table element */
};

#endif /* threads/thread.h */