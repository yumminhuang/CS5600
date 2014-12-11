#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

/* Heuristic for stack growth */
#define STACK_GROWTH_HEURISTIC 32
/* Limit on stack size default to 8 MB */
#define MAX_STACK_SIZE 0x800000
/* Bottom of user virtual memory */
#define USER_VADDR_BOTTOM ((void *) 0x08048000)

void exception_init (void);
void exception_print_stats (void);

#endif /* userprog/exception.h */
