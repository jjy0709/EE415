#include "vm/page.h"
#include <hash.h>
#include "filesys/file.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/swap.h"

struct list lru_list;
struct lock lru_list_lock;
struct list_elem *curr_elem;

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

    // uint8_t *kpage = palloc_get_page (PAL_USER);
    struct page *kpage = alloc_page(PAL_USER);
    if (kpage->kaddr == NULL){
        return false;
    }
    
    kpage->vme = vme;
    if (file_read(vme->f, kpage->kaddr, page_read_bytes) != (int) page_read_bytes)
    {
        // palloc_free_page(kpage);
        free_page(kpage->kaddr);
        return false;
    }
    memset (kpage->kaddr + page_read_bytes, 0, page_zero_bytes);

    if(!install_page(vme->VPN, kpage->kaddr, vme->writable))
    {
        // palloc_free_page(kpage);
        free_page(kpage->kaddr);
        return false;
    }
    return true;
}

void 
lru_list_init()
{
    list_init(&lru_list);
    lock_init(&lru_list_lock);
    curr_elem = list_head(&lru_list);
    // lru_clock NULL?
}

void
add_page_to_lru_list(struct page *page)
{
    lock_acquire(&lru_list_lock);
    list_push_back(&lru_list, &page->lru);
    lock_release(&lru_list_lock);
}

void
del_page_from_lru_list(struct page *page)
{
    lock_acquire(&lru_list_lock);
    list_remove(&page->lru);
    lock_release(&lru_list_lock);
}

static struct list_elem *
get_next_lru_clock(void)
{
    curr_elem = list_next(curr_elem);
    if(curr_elem == list_end(&lru_list))
        return NULL;
    return curr_elem;
}

void
__free_page(struct page *page)
{
    struct vm_entry *vme = page->vme;
    if(vme->VPtype == VM_BIN) {
        if(pagedir_is_dirty(page->thread->pagedir, vme->VPN)) {
            vme->swap_slot = swap_out(page->kaddr);
            vme->VPtype = VM_ANON;
            pagedir_set_dirty(page->thread->pagedir, vme->VPN, 0);
        }
    } else if(vme->VPtype == VM_FILE) {
        if(pagedir_is_dirty(page->thread->pagedir, vme->VPN)) {
            void* buffer = pagedir_get_page(page->thread->pagedir, vme->VPN);
            lock_acquire(&file_lock);
            file_write_at(vme->f, buffer, PGSIZE, vme->offset);
            lock_release(&file_lock);
            pagedir_set_dirty(page->thread->pagedir, vme->VPN, 0);
        }
    } else if(vme->VPtype == VM_ANON) {
        vme->swap_slot = swap_out(page->kaddr);
    }
    del_page_from_lru_list(page);
    vme->is_loaded = false;
    // if(vme->mmap_elem.prev != NULL)
        // list_remove(&vme->mmap_elem);
    // hash_delete(&page->thread->vm, &vme->h_elem);
    pagedir_set_accessed(page->thread->pagedir, vme->VPN, 0);
    pagedir_clear_page(page->thread->pagedir, vme->VPN);
    
    palloc_free_page(page->kaddr); //????????
    free(page);
}

void 
try_to_free_pages(enum palloc_flags flags)
{
    struct list_elem *e = get_next_lru_clock();
    if(e == NULL) {
        curr_elem = list_head(&lru_list);
        return;
    }
    struct page *p = list_entry(e, struct page, lru);
    if(pagedir_is_accessed(p->thread->pagedir, p->vme->VPN)) {
        pagedir_set_accessed(p->thread->pagedir, p->vme->VPN, 0);
    } else {
        __free_page(p);
    }
}

struct page*
alloc_page(enum palloc_flags flags)
{
    void* palloc_page = palloc_get_page(flags);
    while (palloc_page == NULL) {
        try_to_free_pages(flags);
        palloc_page = palloc_get_page(flags);
        // printf("page_set\n");
    }
    // printf("page_allocated!\n");
    struct page *p = malloc(sizeof(struct page));
    p->kaddr = palloc_page;
    p->thread = thread_current();

    add_page_to_lru_list(p);
    return p;
}

void
free_page(void *kaddr)
{
    struct list_elem *e;
    for(e=list_front(&lru_list);e!=list_end(&lru_list);e=list_next(e))
    {
        struct page *p = list_entry(e, struct page, lru);
        if(p->kaddr == kaddr){
            __free_page(p);
            break;
        }
    }
}

