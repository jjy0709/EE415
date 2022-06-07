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
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);

// struct lock file_lock;

void
file_lock_acquire()
{
  // if(file_lock.holder != thread_current())
  //   lock_acquire(&file_lock);
  return;
}

void
file_lock_release()
{
  // if(file_lock.holder == thread_current())
  //   lock_release(&file_lock);
  return;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // lock_init(&file_lock);
}

// bool
// verify_stack(void *addr, void* esp)
// {
//    return((esp-addr <= 0x100) && (esp-addr > 0) && (addr > (PHYS_BASE - 0x8000000)) && (addr <= PHYS_BASE));
// }

struct vm_entry*
check_address (void * addr, void *esp)
{
  if(!is_user_vaddr(addr) || addr < 0x8048000) {
    printf("%s: exit(%d)\n", thread_current()->name, -1);
    thread_current()->exit_status = -1;
    thread_exit();
  }
  struct vm_entry *vme = find_vme(&thread_current()->vm, pg_round_down(addr));
  if(vme == NULL & verify_stack(addr, esp)) {
    // if(buffer + size < )
    expand_stack(addr);
    vme = find_vme(&thread_current()->vm, pg_round_down(addr));
  }
  if(vme == NULL) {
    printf("%s: exit(%d)\n", thread_current()->name, -1);
    thread_current()->exit_status = -1;
    thread_exit();
  }
  vme->pinned = true;
  return vme;
}

void
check_valid_buffer(void*buffer, unsigned size, bool to_write, void* esp)
{
  if(verify_stack(buffer, esp)) {
    void* range = pg_round_down(buffer);
    while(range < buffer + size) {
      check_address(range, esp);
      range += PGSIZE;
    }
  }
  struct vm_entry *vme = check_address(buffer, esp);
  if(to_write && !vme->writable) {
    printf("%s: exit(%d)\n", thread_current()->name, -1);
    thread_current()->exit_status = -1;
    thread_exit();
    vme->pinned = false;
  }
    
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // thread_exit ();
  struct vm_entry *vme = check_address(f->esp, f->esp);
  switch (*(int *)(f->esp))
  {
  // HALT
  case SYS_HALT:
  {
    vme->pinned = false;
    shutdown_power_off();
    break;
  }
  // EXIT
  case SYS_EXIT:
  {
    check_address(f->esp+4, f->esp);
    int status = *(int *)(f->esp+4);
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current()->exit_status = status;
    f->eax = status;
    vme->pinned = false;
    thread_exit();
    break;
  }
  // EXEC
  case SYS_EXEC:
  {
  /* Synchronization */
    check_address(f->esp+4, f->esp);
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
      goto done;
    }
    sema_down(&child->exec_sema);
    if(child->exec_success) {
      f->eax = exec_result;
    } else {
      f->eax = -1;
    }
    goto done;

    #endif
    
    break;
  }
  // WAIT
  case SYS_WAIT:
  {
    check_address(f->esp+4, f->esp);
    pid_t pid = *(int *)(f->esp+4);
    int exit_status = process_wait(pid);
    f->eax = exit_status;
    break;
  }
  // CREATE
  case SYS_CREATE:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    const char *fname = *(char **)(f->esp+4);
    unsigned size = *(unsigned *)(f->esp+8);
    if(fname == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    file_lock_acquire();
    bool res= filesys_create(fname, size, 1);
    file_lock_release();
    f->eax = res;
    break;
  }
  // REMOVE
  case SYS_REMOVE:
  {
    check_address(f->esp+4, f->esp);
    const char *fname = *(char **)(f->esp+4);
    if(fname == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    file_lock_acquire();
    bool res = filesys_remove(fname); 
    file_lock_release();
    f->eax = res;
    break;
  }
  // OPEN
  case SYS_OPEN:
  {
    check_address(f->esp+4, f->esp);
    const char *file = *(char **)(f->esp+4);
    if(file == NULL) {
      printf("%s: exit(%d)\n", thread_current()->name, -1);
      thread_current() -> exit_status = -1;
      thread_exit();
    }
    int i;
    for (i =2; i<=128; i++){
      if (thread_current()->fd[i]==NULL) {
        file_lock_acquire();
        struct file * file_open = filesys_open(file);
        file_lock_release();
        if(file_open == NULL) {
          i = -1;
        } else {
          bool check = check_executable(file);
          if (check) file_deny_write(file_open);
          thread_current()->fd[i]=file_open;
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
    check_address(f->esp+4, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *a = thread_current()->fd[num];
    int res = -1;
    struct inode *inode = file_get_inode(a);
    if (inode_is_file(inode)){
      file_lock_acquire();
      res = (int) file_length(a);
      file_lock_release();
    }
    f->eax = res;
    break;
  }
  // READ
  case SYS_READ:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    check_address(f->esp+12, f->esp);
    int num = *(int *)(f->esp+4);
    void *buffer = f->esp+8;
    // check_address(*(char**)buffer, f->esp);
    unsigned size = *(unsigned *)(f->esp+12);
    check_valid_buffer(*(void**)buffer, size, true, f->esp+12);
    int i;
    if (num == 0){
      for (i=0; i<size; i++){
        if ((**(char **)buffer = input_getc()) == '\0') break;
      }
      f->eax = i;
    }
    else{
      struct file *filename = thread_current()->fd[num];
      off_t res = -1;
      if (inode_is_file(file_get_inode(filename))){
        file_lock_acquire();
        res = file_read(filename, *(void **)buffer, (off_t)size);
        file_lock_release();
      }
      f->eax = res;
    }
    break;
  }
  // WRITE
  case SYS_WRITE:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    check_address(f->esp+12, f->esp);
    int num = *(int *)(f->esp+4); 
    void *buffer = f->esp+8;
    check_address(*(char**)buffer, f->esp);
    unsigned size = *(unsigned *)(f->esp+12);
    check_valid_buffer(*(void**)buffer, size, false, f->esp);
    
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
        off_t res = -1;
        if (inode_is_file(file_get_inode(filename))){
          file_lock_acquire();
          res = file_write(filename, *(const void **)buffer, (off_t)size);
          file_lock_release();
        }
        f->eax = res;
      }
    }
    break;
  }
  // SYS_SEEK
  case SYS_SEEK:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    int num = *(int *)(f->esp+4);
    off_t off = *(off_t *)(f->esp+8);
    struct file *filename = thread_current()->fd[num];
    if (inode_is_file(file_get_inode(filename))){
      file_lock_acquire();
      file_seek(filename, off);
      file_lock_release();
    }
    break;
  }
  // SYS_TELL
  case SYS_TELL:
  {
    check_address(f->esp+4, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    off_t res = -1;
    if (inode_is_file(file_get_inode(filename))){
      file_lock_acquire();
      res = file_tell(filename);
      file_lock_release();
    }
    f->eax = res;
    break;
  }
  case SYS_CLOSE:
  {
    check_address(f->esp+4, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    struct inode *inode = file_get_inode(filename);
    if (inode != NULL){
      if (!inode_is_file(inode)){
        struct dir *dir = (struct dir *)filename;
        dir_close(dir);
      }
      else {
        file_close(filename);;
      }
    }
    thread_current()->fd[num]=NULL;
    break;
  }

  case SYS_MMAP:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    int fd = *(int*)(f->esp+4);
    void *addr = *(uint32_t*)(f->esp+8);

    struct file *file = thread_current()->fd[fd];

    if(pg_ofs(addr) || fd == 0 || fd == 1 || addr == 0 || is_kernel_vaddr(addr) || file == NULL) {
      f->eax = -1;
      goto done;
    }

    off_t length = file_length(file);
    off_t ofs = 0;
    
    if(length == 0) {
      f->eax = -1;
      goto done;
    }

    void* start = addr;
    while(start < addr + length) {
      if(find_vme(&thread_current()->vm, start) != NULL) {
        f->eax = -1;
        goto done;
      }
      start += PGSIZE;
    }

    file_lock_acquire();
    struct file *f2 = file_reopen(file);
    file_lock_release();
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
      vm_entry->VPN = pg_round_down(addr);
      vm_entry->writable = true;
      vm_entry->VPtype = VM_FILE;
      vm_entry->f = f2;
      vm_entry->offset = ofs;
      vm_entry->data_amount = read_bytes;
      vm_entry->is_loaded = false;
      vm_entry->swap_slot = -1;
      vm_entry->pinned = false;
    
      if(!insert_vme(&thread_current()->vm, vm_entry)) {
        goto done;
      }
      list_push_back(&mmap_file->vme_list, &vm_entry->mmap_elem);

      length -= read_bytes;
      ofs += read_bytes;
      addr += PGSIZE;
    }

    f->eax = mmap_file->mapid;
    goto done;
    break;
  }
  case SYS_MUNMAP:
  {
    check_address(f->esp+4, f->esp);
    int mapid = *(int *)(f->esp+4);
    struct list_elem *elem;
    struct mmap_file *mmap_f;
    
    if(list_empty(&thread_current()->mmap_list))
      goto done;
    
    for(elem = list_front(&thread_current()->mmap_list);elem != list_end(&thread_current()->mmap_list);elem = list_next(elem)){
      mmap_f = list_entry(elem, struct mmap_file, elem);
      if(mmap_f->mapid == mapid)
        break;
    }

    if(elem == list_end(&thread_current()->mmap_list)) {
     goto done;
    }
    
    do_munmap(mmap_f);
    
    break;
  }

  case SYS_CHDIR:
  {
    check_address(f->esp+4, f->esp);
    const char *fname = *(char **)(f->esp+4);
    bool success = filesys_chdir(fname);
    f->eax = success;
    break;
  }

  case SYS_MKDIR:
  {
    check_address(f->esp+4, f->esp);
    const char *fname = *(char **)(f->esp+4);
    bool success = filesys_create(fname, 0, 0);
    f->eax = success;
    break;
  }

  case SYS_READDIR:
  {
    check_address(f->esp+4, f->esp);
    check_address(f->esp+8, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    const char *fname = *(char **)(f->esp+8);
    if (filename == NULL){
      f->eax = false;
    }
    else {
      struct inode *inode = file_get_inode(filename);
      if (inode == NULL){
        f->eax = false;
      }
      else{
        if (inode_is_file(inode)){
          f->eax = false;
        }
        else{
          struct dir *dir = (struct dir*) filename;
          f->eax = dir_readdir(dir, fname);
        }
      }
    }
    break;
  }

  case SYS_ISDIR:
  {
    check_address(f->esp+4, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    if (filename == NULL){
      f->eax = false;
    }
    else {
      struct inode *inode = file_get_inode(filename);
      if (inode == NULL){
        f->eax = false;
      }
      else {
        if (inode_is_file(inode)){
          f->eax = false;
        }
        else {
          f->eax = true;
        }
      }
    }
    break;
  }

  case SYS_INUMBER:
  {
    check_address(f->esp+4, f->esp);
    int num = *(int *)(f->esp+4);
    struct file *filename = thread_current()->fd[num];
    if (filename == NULL){
      f->eax = -1;
    }
    else {
      struct inode *inode = file_get_inode(filename);
      if (inode == NULL){
        f->eax = -1;
      }
      else {
        f->eax = inode_sector(inode);
      }
    }
    break;
  }

  default:
  break;
  }
  done:
    vme->pinned = false;
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
  // if(!list_empty(&mmap_file->vme_list))
  // {  
    mmap_elem = list_front(&mmap_file->vme_list);
    while (mmap_elem != list_end(&mmap_file->vme_list))
      {
        struct vm_entry *vm_entry = list_entry(mmap_elem, struct vm_entry, mmap_elem);
        if(vm_entry->is_loaded && pagedir_is_dirty(thread_current()->pagedir, vm_entry->VPN)) {
          void* buffer = pagedir_get_page(thread_current()->pagedir, vm_entry->VPN);
          file_lock_acquire();
          file_write_at(vm_entry->f, buffer, PGSIZE, vm_entry->offset);
          file_lock_release();
          free_page(buffer);
        }
        pagedir_clear_page(thread_current()->pagedir, vm_entry->VPN);
        hash_delete(&thread_current()->vm, &vm_entry->h_elem);
        mmap_elem = list_next(mmap_elem);
        list_remove(&vm_entry->mmap_elem);
        free(vm_entry);
      }
  // }
  list_remove(&mmap_file->elem);
  file_lock_acquire();
  file_close(mmap_file->file);
  file_lock_release();
  free(mmap_file);
}
