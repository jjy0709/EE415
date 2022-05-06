#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "vm/page.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

void
check_address (void * addr)
{
  if(!is_user_vaddr(addr) || addr < 0x8048000) {
    printf("%s: exit(%d)\n", thread_current()->name, -1);
    thread_current()->exit_status = -1;
    thread_exit();
  }
  
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
    f->eax = status;
    thread_exit();
    break;
  }
  // EXEC
  case SYS_EXEC:
  {
  /* Synchronization */
    check_address(f->esp+4);
    const char *cmd = *(char **)(f->esp+4);
    char *fn_copy = palloc_get_page(0);
    strlcpy(fn_copy, cmd, PGSIZE);

    tid_t exec_result = process_execute(fn_copy);
    palloc_free_page(fn_copy);
    #ifdef USERPROG
    struct list_elem *e;
    struct thread *child;
    for(e = list_front(&thread_current()->children); e != list_end(&thread_current()->children); e = list_next(e)) {
      child = list_entry(e, struct thread, child_elem);
      if(child->tid == exec_result) break;
    }
    if(e == list_end(&thread_current()->children)) {
      f->eax = -1;
      return;
    }
    sema_down(&child->exec_sema);
    if(child->exec_success) {
      f->eax = exec_result;
    } else {
      f->eax = -1;
    }
    return;

    #endif
    
    break;
  }
  // WAIT
  case SYS_WAIT:
  {
    check_address(f->esp+4);
    pid_t pid = *(int *)(f->esp+4);
    int exit_status = process_wait(pid);
    f->eax = exit_status;
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
    lock_acquire(&file_lock);
    bool res= filesys_create(fname, size);
    lock_release(&file_lock);
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
    lock_acquire(&file_lock);
    bool res = filesys_remove(fname); 
    lock_release(&file_lock);
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
        lock_acquire(&file_lock);
        struct file * f = filesys_open(file);
        lock_release(&file_lock);
        if(f == NULL) {
          i = -1;
        } else {
          bool check = check_executable(file);
          if (check) file_deny_write(f);
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
    lock_acquire(&file_lock);
    int res = (int)file_length(a);
    lock_release(&file_lock);
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
      lock_acquire(&file_lock);
      off_t res = file_read(filename, *(void **)buffer, (off_t)size);
      lock_release(&file_lock);
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
    
    if(num < 0 || num > 128) {
      f->eax = -1;
    }
    else if(num == 1) {
      putbuf(*(const char **)buffer, (size_t) size);
      f->eax = size;
    }
    else{
      struct file *filename = thread_current()->fd[num];
      if(filename == NULL) {
        f->eax = -1;
      } else {
        lock_acquire(&file_lock);
        off_t res = file_write(filename, *(const void **)buffer, (off_t)size);
        lock_release(&file_lock);
        f->eax = res;
      }
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
    lock_acquire(&file_lock);
    file_seek(filename, off);
    lock_release(&file_lock);
    break;
  }
  // SYS_TELL
  case SYS_TELL:
  {
    check_address(f->esp+4);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    lock_acquire(&file_lock);
    off_t res = file_tell(filename);
    lock_release(&file_lock);
    f->eax = res;
    break;
  }
  case SYS_CLOSE:
  {
    check_address(f->esp+4);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    lock_acquire(&file_lock);
    file_close(filename);
    lock_release(&file_lock);
    thread_current()->fd[num]=NULL;
    break;
  }
  case SYS_MMAP:
  {
    check_address(f->esp+4);
    check_address(f->esp+8);
    int fd = *(int*)(f->esp+4);
    void *addr = *(uint32_t*)(f->esp+8);

    struct file *file = thread_current()->fd[fd];

    if(pg_ofs(addr) || fd == 0 || fd == 1 || addr == 0 || is_kernel_vaddr(addr) || file == NULL) {
      f->eax = -1;
      return -1;
    }

    off_t length = file_length(file);
    off_t ofs = 0;
    
    if(length == 0) {
      f->eax = -1;
      return -1;
    }

    void* start = addr;
    while(start < addr + length) {
      if(find_vme(&thread_current()->vm, start) != NULL) {
        f->eax = -1;
        return -1;
      }
      start += PGSIZE;
    }

    struct file *f2 = file_reopen(file);
    struct mmap_file *mmap_file = malloc(sizeof(struct mmap_file));
    mmap_file->file = f2;
    mmap_file->mapid = list_size(&thread_current()->mmap_list);
    list_push_back(&thread_current()->mmap_list, &mmap_file->elem);
    list_init(&mmap_file->vme_list);

    while (length > 0)
    {
      size_t read_bytes = length < PGSIZE ? length : PGSIZE;
      size_t zero_bytes = PGSIZE - read_bytes;

      struct vm_entry *vm_entry = malloc(sizeof (struct vm_entry));
      vm_entry->VPN = addr;
      vm_entry->writable = true;
      vm_entry->VPtype = VM_FILE;
      vm_entry->f = f2;
      vm_entry->offset = ofs;
      vm_entry->data_amount = read_bytes;
      vm_entry->is_loaded = false;
    
      if(!insert_vme(&thread_current()->vm, vm_entry)) {
        return false;
      }
      list_push_back(&mmap_file->vme_list, &vm_entry->mmap_elem);

      length -= read_bytes;
      ofs += read_bytes;
      addr += PGSIZE;
    }

    f->eax = mmap_file->mapid;
    return;
    break;
  }
  case SYS_MUNMAP:
  {
    check_address(f->esp+4);
    int mapid = *(int *)(f->esp+4);
    struct list_elem *elem;
    struct mmap_file *mmap_f;
    
    if(list_empty(&thread_current()->mmap_list))
      return -1;
    
    for(elem = list_front(&thread_current()->mmap_list);elem != list_end(&thread_current()->mmap_list);elem = list_next(elem)){
      mmap_f = list_entry(elem, struct mmap_file, elem);
      if(mmap_f->mapid == mapid) 
        do_munmap(mmap_f);
        break;
    }

    if(elem == list_end(&thread_current()->mmap_list)) {
     return -1;
    }
    
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

void do_munmap(struct mmap_file *mmap_file) {
  struct list_elem *mmap_elem;
  if(!list_empty(&mmap_file->vme_list))
  {  
    mmap_elem = list_front(&mmap_file->vme_list);
    while (mmap_elem != list_end(&mmap_file->vme_list))
      {
        struct vm_entry *vm_entry = list_entry(mmap_elem, struct vm_entry, mmap_elem);
        if(vm_entry->is_loaded && pagedir_is_dirty(thread_current()->pagedir, vm_entry->VPN)) {
          void* buffer = pagedir_get_page(thread_current()->pagedir, vm_entry->VPN);
          file_write_at(vm_entry->f, buffer, PGSIZE, vm_entry->offset);
        }
        pagedir_clear_page(thread_current()->pagedir, vm_entry->VPN);
        hash_delete(&thread_current()->vm, &vm_entry->h_elem);
        mmap_elem = list_next(mmap_elem);
        free(vm_entry);
      }
  }
  list_remove(&mmap_file->elem);
  file_close(mmap_file->file);
  free(mmap_file);
}