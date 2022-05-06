#include "vm/page.h"
#include <hash.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"


void
vm_init (struct hash* vm)
{
    hash_init(vm, vm_hash_func, vm_less_func, NULL);

}

void
vm_destroy (struct hash *vm)
{
    hash_destroy(vm, vm_destroy_func);
}

bool
insert_vme (struct hash *vm, struct vm_entry *vme)
{
    if(hash_insert(vm, &vme->h_elem) == NULL)
        return true;
    else
        return false;
}

bool
delete_vme (struct hash *vm, struct vm_entry *vme)
{
    hash_delete(vm, &vme->h_elem);
}

struct vm_entry *
find_vme (struct hash *vm, void *vaddr)
{
    struct hash_elem *e;
    struct vm_entry vm_entry;
    vm_entry.VPN = vaddr;

    e = hash_find(vm, &vm_entry.h_elem);
    if(e == NULL) return NULL;
    else {
        return hash_entry(e, struct vm_entry, h_elem);
    }
}

static unsigned
vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *vmE = hash_entry(e, struct vm_entry, h_elem);
    
    return hash_bytes(&vmE->VPN, sizeof vmE->VPN);
}

static bool
vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct vm_entry *vmE_a = hash_entry(a, struct vm_entry, h_elem);
    struct vm_entry *vmE_b = hash_entry(b, struct vm_entry, h_elem);

    return (vmE_a->VPN < vmE_b->VPN);
}

static void
vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *vm_entry = hash_entry(e, struct vm_entry, h_elem);
    free(vm_entry);
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool
load_file (void *kaddr, struct vm_entry *vme)
{
    
    file_seek (vme->f, vme->offset);

    size_t page_read_bytes = vme->data_amount < PGSIZE ? vme->data_amount : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    uint8_t *kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
        return false;
    
    if (file_read(vme->f, kpage, page_read_bytes) != (int) page_read_bytes)
    {
        palloc_free_page(kpage);
        return false;
    }
    memset (kpage + page_read_bytes, 0, page_zero_bytes);

    if(!install_page(vme->VPN, kpage, vme->writable))
    {
        palloc_free_page(kpage);
        return false;
    }
    return true;
}

