#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

extern struct lock file_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
