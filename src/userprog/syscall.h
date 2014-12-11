#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


void syscall_init (void);
void exit (int status);

/* Map region identifier. */
typedef int mapid_t;
/* Failure status code of mmap operation */
#define MAP_FAILED ((mapid_t) -1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

#endif /* userprog/syscall.h */
