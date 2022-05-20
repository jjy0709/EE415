#include "buffer_cache.h"
#include <string.h>
#include "threads/malloc.h"
#include "filesys/filesys.h"

#define BUFFER_CACHE_ENTRY_NB 64

static char p_buffer_cache[BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE];
static struct buffer_head buffer_head[BUFFER_CACHE_ENTRY_NB];
struct buffer_head *clock_hand;

struct lock bh_lock;

void
bc_init(void)
{
    struct buffer_head *b;
    void* buffer;
    b = buffer_head;
    buffer = p_buffer_cache;
    while(b != buffer_head + BUFFER_CACHE_ENTRY_NB) {
        b->data = buffer;
        lock_init(&b->lock);
        buffer += BLOCK_SECTOR_SIZE;
        b++;
    }
    lock_init(&bh_lock);
    clock_hand = buffer_head;
}

void
bc_term(void)
{
    bc_flush_all_entries();
}

struct buffer_head*
bc_lookup (block_sector_t sector_idx)
{
    struct buffer_head *b = buffer_head;
    while(b != buffer_head + BUFFER_CACHE_ENTRY_NB) {
        if(b->sector == sector_idx && b->used) break;
        b++;
    }
    if(b == buffer_head + BUFFER_CACHE_ENTRY_NB) return NULL;
    else return b;
}

struct buffer_head*
bc_select_victim ()
{
    while(clock_hand->referenced) {
        clock_hand->referenced = false;
        clock_hand++;
        if(clock_hand == buffer_head + BUFFER_CACHE_ENTRY_NB) clock_hand = buffer_head;
    }
    if(clock_hand->dirty) bc_flush_entry(clock_hand);
    clock_hand->used = false;
    memset(clock_hand->data, 0, BLOCK_SECTOR_SIZE);
    struct buffer_head* victim = clock_hand;
    clock_hand++;
    if(clock_hand == buffer_head + BUFFER_CACHE_ENTRY_NB) clock_hand = buffer_head;
    return victim;
}

bool
bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{
    lock_acquire(&bh_lock);
    struct buffer_head *bh;
    bh = bc_lookup(sector_idx);
    if(!bh) {
        bh = bc_select_victim();
        lock_acquire(&bh->lock);
        block_read(fs_device, sector_idx, bh->data);
        bh->used = true;
        bh->sector = sector_idx;
        bh->dirty = false;
        bh->referenced = true;
        lock_release(&bh->lock);
    }
    memcpy(buffer+bytes_read, bh->data+sector_ofs, chunk_size);
    bh->referenced = true;
    lock_release(&bh_lock);
    return true;
}

bool
bc_write (block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
    lock_acquire(&bh_lock);
    bool success = false;
    struct buffer_head *bh = bc_lookup(sector_idx);
    if(bh == NULL) {
        bh = bc_select_victim();
        lock_acquire(&bh->lock);
        block_read(fs_device, sector_idx, bh->data);
        bh->used = true;
        bh->sector = sector_idx;
        bh->dirty = false;
        bh->referenced = true;
        lock_release(&bh->lock);
    }
    memcpy(bh->data + sector_ofs, buffer + bytes_written, chunk_size);
    bh->dirty = true;
    bh->referenced = true;
    lock_release(&bh_lock);
    return true;
}

void
bc_flush_entry (struct buffer_head *p_flush_entry) 
{
    lock_acquire(&p_flush_entry->lock);
    block_write(fs_device, p_flush_entry->sector, p_flush_entry->data);
    p_flush_entry -> dirty = false;
    lock_release(&p_flush_entry->lock);
}

void
bc_flush_all_entries ()
{
    struct buffer_head *b = buffer_head;
    while(b != buffer_head + BUFFER_CACHE_ENTRY_NB) {
        if(b->dirty) bc_flush_entry(b);
        b++;
    }
}