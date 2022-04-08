#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  switch (*(int*)f->esp)
  {
  case SYS_EXIT:
    int status = *(int *)(f->esp+4);

    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current() -> exit_status = status;
    thread_exit();
    break;
  case SYS_WRITE:
    int fd = *(int *)(f->esp+4); 
    void *buffer = f->esp+8; 
    unsigned size = *(unsigned *)(f->esp+12);
    
    if(fd == 1) {
      // printf("%s\n", (char*)buffer);
      putbuf(*(const char **)buffer, (size_t) size);
    }
    f->eax = size;


    break;
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
