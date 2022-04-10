#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

static struct semaphore exec_sema;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
tid_t process_exec_wait (const char *file_name);

#endif /* userprog/process.h */
