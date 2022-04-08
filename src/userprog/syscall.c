#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
check_address (void * addr)
{
  // printf("check_addr\n");
  // for(int i = 0; i<4; i++){
    if(!is_user_vaddr(addr) || addr < 0x8048000) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current()->exit_status = -1;
      thread_exit();
    }
  // }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // thread_exit ();
  check_address(f->esp);
  switch (*(int *)(f->esp))
  {
  // HALT
  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }
  // EXIT
  case SYS_EXIT:
  {
    check_address(f->esp+4);
    int status = *(int *)(f->esp+4);
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current()->exit_status = status;
    thread_exit();
    f->eax = status;
    break;
  }
  // EXEC
  case SYS_EXEC:
  {
  /* Synchronization */
    check_address(f->esp+4);
    const char *cmd = *(char **)(f->esp+4);
    int exec_result = process_execute(cmd);
    f->eax = exec_result;
    break;
  }
  // WAIT
  case SYS_WAIT:
  {
    check_address(f->esp+4);
    pid_t pid = *(int *)(f->esp+4);
    process_wait(pid);
    break;
  }
  // CREATE
  case SYS_CREATE:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    const char *fname = *(char **)(f->esp+4);
    unsigned size = *(unsigned *)(f->esp+8);
    if(fname == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    bool res= filesys_create(fname, size);
    f->eax = res;
    break;
  }
  // REMOVE
  case SYS_REMOVE:
  {
    check_address(f->esp+4);
    const char *fname = *(char **)(f->esp+4);
    if(fname == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    bool res = filesys_remove(fname); 
    f->eax = res;
    break;
  }
  // OPEN
  case SYS_OPEN:
  {
    check_address(f->esp+4);
    const char *file = *(char **)(f->esp+4);
    if(file == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    int i;
    for (i =2; i<=128; i++){
      if (thread_current()->fd[i]==NULL) {
        struct file * f = filesys_open(file);
        if(f == NULL) {
          i = -1;
        } else {
          thread_current()->fd[i]=f;
        }
        break;
      }
    }
    f->eax = i;
    break;
  }
  // FILESIZE
  case SYS_FILESIZE:
  {
    check_address(f->esp+4);
    int num = *(int *)(f->esp+4);
    struct file *a = thread_current()->fd[num]; 
    int res = (int)file_length(a);
    f->eax = res;
    break;
  }
  // READ
  case SYS_READ:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    check_address(f->esp+12);
    int num = *(int *)(f->esp+4);
    void *buffer = f->esp+8;
    check_address(*(char**)buffer);
    unsigned size = *(unsigned *)(f->esp+12);
    int i;
    if (num == 0){
      for (i=0; i<size; i++){
        if ((**(char **)buffer = input_getc()) == '\0') break;
      }
      f->eax = i;
    }
    else{
      struct file *filename = thread_current()->fd[num];
      off_t res = file_read(filename, *(void **)buffer, (off_t)size);
      f->eax = res;
    }
    break;
  }
  // WRITE
  case SYS_WRITE:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    check_address(f->esp+12);
    int num = *(int *)(f->esp+4); 
    void *buffer = f->esp+8; 
    unsigned size = *(unsigned *)(f->esp+12);
    
    if(num == 1) {
      putbuf(*(const char **)buffer, (size_t) size);
      f->eax = size;
    }

    else{
      struct file *filename = thread_current()->fd[num];
      off_t res = file_write(filename, *(const void **)buffer, (off_t)size);
      f->eax = res;
    }
    break;
  }
  // SYS_SEEK
  case SYS_SEEK:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    int num = *(int *)(f->esp+4);
    off_t off = *(off_t *)(f->esp+8);
    struct file *filename = thread_current()->fd[num];
    file_seek(filename, off);
    break;
  }
  // SYS_TELL
  case SYS_TELL:
  {
    check_address(f->esp+4);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    off_t res = file_tell(filename);
    f->eax = res;
    break;
  }
  case SYS_CLOSE:
  {
    check_address(f->esp+4);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    file_close(filename);
    thread_current()->fd[num]=NULL;
    break;
  }

  case SYS_SIGACTION:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    int signum = *(int *)(f->esp+4);
    void(*handler)() = *(void **)(f->esp+8);
    // thread_current()->
    break;
  }

  case SYS_SENDSIG:
    break;

  case SYS_YIELD:
  {
    thread_yield();
    break;
  }

  default:
  break;
  }
  // thread_exit ();
}

// SYS_EXIT,                   /* Terminate this process. */
//     SYS_EXEC,                   /* Start another process. */
//     SYS_WAIT,                   /* Wait for a child process to die. */
//     SYS_CREATE,                 /* Create a file. */
//     SYS_REMOVE,                 /* Delete a file. */
//     SYS_OPEN,                   /* Open a file. */
//     SYS_FILESIZE,               /* Obtain a file's size. */
//     SYS_READ,                   /* Read from a file. */
//     SYS_WRITE,                  /* Write to a file. */
//     SYS_SEEK,                   /* Change position in a file. */
//     SYS_TELL,                   /* Report current position in a file. */
//     SYS_CLOSE,                  /* Close a file. */
//     SYS_SIGACTION,              /* Register an signal handler */
//     SYS_SENDSIG,                /* Send a signal */
//     SYS_YIELD, 
