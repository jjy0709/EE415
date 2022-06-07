#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size, uint32_t is_file);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

char* extract_name(const char* full_path);
struct dir* name_to_dir(const char* full_path);
bool filesys_chdir(const char* name);
bool is_current(char *name);
bool is_prev(char *name);

#endif /* filesys/filesys.h */
