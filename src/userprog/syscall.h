#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef void sig_handler (void);

struct signal_handler {
    sig_handler *handle_func;
    int sig_num;
};

typedef int pid_t;

// extern struct lock file_lock;
void file_lock_acquire(void);
void file_lock_release(void);

void syscall_init (void);

#endif /* userprog/syscall.h */
