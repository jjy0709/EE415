#include "filesys/off_t.h"
#include <hash.h>

enum VP_type {
    VM_BIN = 0,
    VM_FILE = 1,
    VM_ANON = 2
};

struct vm_entry {
    enum VP_type VPtype;
    void* VPN;
    struct hash_elem h_elem;
    bool writable;

    bool is_loaded;
    struct file *f;
    
    struct list_elem mmap_elem;

    off_t offset;
    size_t data_amount;

    size_t swap_slot;
};

struct mmap_file {
    int mapid;
    struct file *file;
    struct list_elem elem;
    struct list vme_list;
};

void vm_init(struct hash*);
void vm_destroy (struct hash*);

bool insert_vme (struct hash *, struct vm_entry *);
bool delete_vme (struct hash *, struct vm_entry *);
struct vm_entry* find_vme (struct hash *, void*);

static unsigned vm_hash_func(const struct hash_elem *, void *);
static bool vm_less_func(const struct hash_elem *, const struct hash_elem *, void *);
static void vm_destroy_func(struct hash_elem *, void *);

bool load_file (void *, struct vm_entry *);