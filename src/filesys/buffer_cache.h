#include "devices/block.h"
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/synch.h"

struct buffer_head
{
    // struct inode *inode;
    bool dirty;
    bool used;
    bool referenced;
    struct lock lock;
    block_sector_t sector;
    void* data;
};

void bc_init (void);
void bc_term (void);

bool bc_read (block_sector_t, void*, off_t, int, int);
bool bc_write (block_sector_t, void*, off_t, int, int);

struct buffer_head* bc_lookup (block_sector_t);
struct buffer_head* bc_select_victim (void);

void bc_flush_entry (struct buffer_head *);
void bc_flush_all_entries (void);