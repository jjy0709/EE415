#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/buffer_cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCKS 118
#define NUM_BLOCK 128 // 512 / 4 = 128
uint32_t null_buffer[NUM_BLOCK];

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    // 2*4
    // block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */             
    block_sector_t prev; // address of prev directory of this file (default is root)

    // (direct_blocks + 2)*4
    block_sector_t direct_map_table[DIRECT_BLOCKS];
    block_sector_t indirect_block;
    block_sector_t double_indirect_block;
    // 3*4
    uint32_t direct_index; // from 0 to DIRECT_BLOCKS
    uint32_t indirect_index; // from 0 to NUM_BLOCK
    uint32_t double_indirect_index;
    uint32_t double_indirect_indirect_index;
    // 1*4
    uint32_t is_file; // is this a directory? 0 for no (file), nonzero for yes

  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */ // diskinode location
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */

    // Copied disk_inode contents
    // For Sync
    off_t length;                       /* File size in bytes. */

    // Suppose processes A and B both have a given file open and both are positioned at end-of-file. 
    // If A reads and B writes the file at the same time, A read NONE of what B writes.
    // We update before_length when write_at finishes.
    unsigned magic;                     /* Magic number. */
    block_sector_t prev;

    block_sector_t direct_map_table[DIRECT_BLOCKS];
    block_sector_t indirect_block;
    block_sector_t double_indirect_block;
    // 3*4
    uint32_t direct_index;
    uint32_t indirect_index;
    uint32_t double_indirect_index;
    uint32_t double_indirect_indirect_index;
    uint32_t is_file;

    off_t before_extension_length;
    // Extending file must be atomic
    struct lock extend_lock;
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos, bool read) 
{
  ASSERT (inode != NULL);
  int length;
  if (read) length = inode->before_extension_length;
  else length = inode->length;

  block_sector_t indirect_block[NUM_BLOCK];
  block_sector_t double_indirect_block[NUM_BLOCK];

  if (pos >= length) return -1;

  else if (pos < DIRECT_BLOCKS * BLOCK_SECTOR_SIZE){
    return inode->direct_map_table[pos / BLOCK_SECTOR_SIZE];
  }

  else if (pos < DIRECT_BLOCKS * BLOCK_SECTOR_SIZE + NUM_BLOCK * BLOCK_SECTOR_SIZE){
    block_read(fs_device, inode->indirect_block, &indirect_block);
    int pos2 = pos - DIRECT_BLOCKS * BLOCK_SECTOR_SIZE;
    int index = pos2 / BLOCK_SECTOR_SIZE; // index in indirect block
    return indirect_block[index];
  }

  else {
    block_read(fs_device, inode->double_indirect_block, &double_indirect_block);
    int pos2 = pos - DIRECT_BLOCKS * BLOCK_SECTOR_SIZE - NUM_BLOCK * BLOCK_SECTOR_SIZE;
    int index = pos2 / (NUM_BLOCK * BLOCK_SECTOR_SIZE);
    block_read(fs_device, double_indirect_block[index], &indirect_block);
    int pos3 = pos2 % (NUM_BLOCK * BLOCK_SECTOR_SIZE);
    int index2 = pos3 / BLOCK_SECTOR_SIZE; 
    return indirect_block[index2];
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t is_file)
{
  struct inode_disk *disk_inode = NULL;
  struct inode *node = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      node = calloc (1, sizeof *node);
      inode_extend(node, length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->direct_index = node->direct_index;
      disk_inode->indirect_index = node->indirect_index;
      disk_inode->double_indirect_index = node->double_indirect_index;
      disk_inode->double_indirect_indirect_index = node->double_indirect_indirect_index;
      for (int counter = 0; counter < DIRECT_BLOCKS; counter++){
        disk_inode->direct_map_table[counter] = node->direct_map_table[counter];
      }
      disk_inode->indirect_block = node->indirect_block;
      disk_inode->double_indirect_block = node->double_indirect_block;
      disk_inode->is_file = is_file;
      disk_inode->prev = ROOT_DIR_SECTOR;

      block_write(fs_device, sector, disk_inode);
      success = true;
      free(node);
      free(disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  struct inode_disk *disk_inode;
  disk_inode = calloc(1, sizeof *disk_inode);
  list_push_front (&open_inodes, &inode->elem);
  lock_init(&inode->extend_lock);
  inode->sector = sector;
  inode->magic = INODE_MAGIC;
  block_read (fs_device, inode->sector, disk_inode);
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->length = disk_inode->length;
  inode->before_extension_length = disk_inode->length;
  for (int counter = 0; counter < DIRECT_BLOCKS; counter++){
    inode->direct_map_table[counter] = disk_inode->direct_map_table[counter];
  }
  inode->indirect_block = disk_inode->indirect_block;
  inode->double_indirect_block = disk_inode->double_indirect_block;

  inode->direct_index = disk_inode->direct_index;
  inode->indirect_index = disk_inode->indirect_index;
  inode->double_indirect_index = disk_inode->double_indirect_index;
  inode->double_indirect_indirect_index = disk_inode->double_indirect_indirect_index;

  inode->is_file = disk_inode->is_file;
  inode->prev = disk_inode->prev;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  struct buffer_head *bh = bc_lookup(inode->sector);
  if(bh && bh->dirty) {
    bc_flush_entry(bh);
  }

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          size_t to_free = bytes_to_sectors(inode->length);

          int counter = 0;
          while (counter < inode->direct_index && to_free != 0) {
            free_map_release (inode->direct_map_table[counter],1);
            to_free--;
            counter++;
          }
          int counter2 = 0;
          block_sector_t indirect_blocks[NUM_BLOCK];
          block_sector_t double_indirect_blocks[NUM_BLOCK];
          if (to_free != 0){
            block_read(fs_device, inode->indirect_block, &indirect_blocks);
            while (counter2 < inode->indirect_index && to_free != 0) {
              free_map_release (indirect_blocks[counter2],1);
              counter2++;
              to_free--;
            }
            free_map_release(inode->indirect_block, 1);
          }

          if (to_free != 0){
            block_read(fs_device, inode->double_indirect_block, &double_indirect_blocks);
            int counter3 = 0;
            while (counter3 < inode->double_indirect_index && to_free != 0){
              int counter4 = 0;
              block_read(fs_device, double_indirect_blocks[counter3], &indirect_blocks);
              while (counter4 < NUM_BLOCK && to_free != 0) {
                free_map_release (indirect_blocks[counter4], 1);
                counter4++;
                to_free--;
              }
              free_map_release (double_indirect_blocks[counter3], 1);
              counter3++;
            }
            free_map_release (inode->double_indirect_block, 1);
          }

        }
      else {
        struct inode_disk *disk_inode = NULL;
        disk_inode = calloc(1, sizeof *disk_inode);
        disk_inode->length = inode->length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->direct_index = inode->direct_index;
        disk_inode->indirect_index = inode->indirect_index;
        disk_inode->double_indirect_index = inode->double_indirect_index;
        disk_inode->double_indirect_indirect_index = inode->double_indirect_indirect_index;
        for (int counter = 0; counter < DIRECT_BLOCKS; counter++){
          disk_inode->direct_map_table[counter] = inode->direct_map_table[counter];
        }
        disk_inode->indirect_block = inode->indirect_block;
        disk_inode->double_indirect_block = inode->double_indirect_block;
        disk_inode->is_file = inode->is_file;
        disk_inode->prev = inode->prev;
        block_write(fs_device, inode->sector, disk_inode);
        }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  // uint8_t *bounce = NULL;

  if (byte_to_sector(inode, offset, true) == -1 ) return 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset, true);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  // free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  // uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (size + offset > inode->length){
    if(inode->is_file != 0) lock_acquire(&inode->extend_lock);

    inode->length = inode_extend(inode, offset + size);

    while (size > 0) 
      {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector (inode, offset, false);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length (inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
          break;

        bc_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
      }
    if(inode->is_file != 0) lock_release(&inode->extend_lock);
    inode->before_extension_length = inode->length;
    return bytes_written;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset, false);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  // free (bounce);
  inode->before_extension_length = inode->length;
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->length;
}


// Should be atomic
off_t
inode_extend (struct inode *inode, off_t to_extend)
{
  size_t to_grow = bytes_to_sectors(to_extend) - bytes_to_sectors(inode->length);
  // No need to extend
  if (to_grow <= 0)
  {
    return to_extend;
  }

  while(inode->direct_index < DIRECT_BLOCKS && to_grow != 0){
    if (free_map_allocate(1, &inode->direct_map_table[inode->direct_index])){
      // fill with 0
      block_write(fs_device, inode->direct_map_table[inode->direct_index], null_buffer);
      inode->direct_index++;
      to_grow--;
    };
  }

  block_sector_t indirect_block[NUM_BLOCK];
  block_sector_t double_indirect_block[NUM_BLOCK];
  if (inode->indirect_index < NUM_BLOCK && to_grow !=0){
    if (inode->indirect_index == 0){
      free_map_allocate(1, &inode->indirect_block);
    }
    else {
      block_read(fs_device, inode->indirect_block, &indirect_block);
    }
    while (inode->indirect_index < NUM_BLOCK && to_grow !=0){
      free_map_allocate(1, &indirect_block[inode->indirect_index]);
      block_write(fs_device, indirect_block[inode->indirect_index], null_buffer);
      inode->indirect_index++;
      to_grow--;
    }
    block_write(fs_device, inode->indirect_block, &indirect_block);
  }
  
  if (to_grow != 0){
    if (inode->double_indirect_index == 0 && inode->double_indirect_indirect_index == 0){
      free_map_allocate(1, &inode->double_indirect_block);
    }
    else {
      block_read(fs_device, inode->double_indirect_block, &double_indirect_block);
    }
    while (inode->double_indirect_index < NUM_BLOCK && to_grow !=0){
      if (inode->double_indirect_indirect_index == 0){
        free_map_allocate(1, &double_indirect_block[inode->double_indirect_index]);
      }
      else {
        block_read(fs_device, double_indirect_block[inode->double_indirect_index], &indirect_block);
      }
      while (inode->double_indirect_indirect_index < NUM_BLOCK && to_grow != 0){
        free_map_allocate(1, &indirect_block[inode->double_indirect_indirect_index]);
        block_write(fs_device, indirect_block[inode->double_indirect_indirect_index], null_buffer);
        inode->double_indirect_indirect_index++;
        to_grow--;
      }
      block_write(fs_device, double_indirect_block[inode->double_indirect_index], &indirect_block);
    }
    if (inode->double_indirect_indirect_index == NUM_BLOCK){
      inode->double_indirect_indirect_index = 0;
      inode->double_indirect_index++;
    }
    block_write(fs_device, inode->double_indirect_block, &double_indirect_block);
    if (inode->double_indirect_index == NUM_BLOCK && to_grow != 0){
      // Trying to allocate too large file
      return -1;
    }
  }  
  return to_extend;
}

bool 
inode_is_file(struct inode *inode){
  if (inode->is_file != 0){
    return true;
  }
  else {
    return false;
  }
}

block_sector_t
inode_sector(struct inode *inode){
  return inode->sector;
}

void
inode_set_prev(block_sector_t current, block_sector_t to_set){

  struct inode* inode = inode_open(to_set);
  if (inode == NULL) return;
  inode->prev = current;
  inode_close(inode);
  return;
}

block_sector_t
inode_get_prev(struct inode *inode){
  return inode->prev;
}

int
inode_open_cnt(struct inode *inode){
  return inode->open_cnt;
}
