#include "vm/swap.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include <stdio.h>

struct bitmap *swap_bitmap;
struct block *swap_partition;

size_t s_per_p = PGSIZE/BLOCK_SECTOR_SIZE;

void
swap_init(void)
{
    swap_partition = block_get_role(BLOCK_SWAP);
    if(swap_partition == NULL){
        return;
    }
    swap_bitmap = bitmap_create(block_size(swap_partition)/s_per_p);

}

void
swap_in(size_t used_index, void* kaddr)
{
    size_t s = 0;
    while(s < s_per_p) {
        block_read(swap_partition, used_index*s_per_p + s, kaddr + s*BLOCK_SECTOR_SIZE);
        s++;
    }
    bitmap_set(swap_bitmap, used_index, false);
}

size_t
swap_out(void *kaddr)
{
    if(swap_bitmap == NULL) {
        swap_init();
    }
    size_t index = bitmap_scan(swap_bitmap, 0, 1, false);
    if(index == BITMAP_ERROR) {
        printf("ERROR");
        return;
    }
    // 여기서 자리 없으면 뭔가 늘려야 하는듯
    size_t s = 0;
    while(s < s_per_p) {
        block_write(swap_partition,index*s_per_p+s, kaddr + s*BLOCK_SECTOR_SIZE);
        s++;
    }
    bitmap_set(swap_bitmap, index, true);
    return index;
}

void
swap_delete(size_t swap_slot)
{
    bitmap_set(swap_bitmap, swap_slot, false);
}

