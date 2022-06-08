#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "filesys/buffer_cache.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  bc_init();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  bc_term();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, uint32_t is_file) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = name_to_dir(name);
  char *name2 = extract_name(name);
  if (!strlen(name)){
    free(name2);
    return false;
  }

  bool success = false;
  if (!(is_current(name2) || is_prev(name2))){
    success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_file)
                  && dir_add (dir, name2, inode_sector));
  }
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  free(name2);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = name_to_dir(name);
  char *name2 = extract_name(name);
  if (!strlen(name)){
    free(name2);
    return NULL;
  }
  struct inode *inode = NULL;

  if (dir != NULL){
    if (is_current(name2)){
      free(name2);
      return (struct file *) dir;
    }
    else if (is_prev(name2)){
      block_sector_t sector = inode_get_prev(dir_get_inode(dir));
      inode = inode_open(sector);
      if (inode == NULL){
        free(name2);
        return NULL;
      }
    }
    else if (inode_get_inumber(dir_get_inode(dir)) == ROOT_DIR_SECTOR){
      if (strlen(name2) == 0){
        free(name2);
        return (struct file *) dir;
      }
      else {
        dir_lookup(dir, name2, &inode);
      }
    }
    else {
      dir_lookup(dir, name2, &inode);
    }
  }
  dir_close (dir);
  free(name2);
  if (inode != NULL){
    if (!inode_is_file(inode)){
      return (struct file *)dir_open(inode);
    }
    else{
      return file_open(inode);
    }
  }
  return NULL;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = name_to_dir(name);
  char *name2 = extract_name(name);
  if (!strlen(name)) {
    free(name2);
    return false;
  }
  bool success = dir != NULL && dir_remove (dir, name2);
  dir_close (dir); 
  free(name2);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

char*
extract_name(const char* full_path)
{
  char path[strlen(full_path) + 1];
  memcpy(path, full_path, strlen(full_path) + 1);  

  char *cur = "";
  char *prev = "";
  char *saveptr = NULL;
  cur = strtok_r(path, "/", &saveptr);
  while (cur != NULL){
    prev = cur;
    cur = strtok_r(NULL, "/", &saveptr);
  } 
  // Need to free name afterwards
  // if (prev==NULL){
  //   return NULL;
  // }
  char* name = (char *)malloc(strlen(prev) + 1);
  memcpy(name, prev, strlen(prev));
  name[strlen(prev)] = '\0';
  return name;
}

struct dir*
name_to_dir(const char* full_path)
{
  char path[strlen(full_path) + 1];
  memcpy(path, full_path, strlen(full_path) + 1);

  struct dir* dir;
  if(path[0] == '/' || thread_current() -> cur_dir == NULL) dir = dir_open_root();
  else dir = dir_reopen (thread_current() -> cur_dir);
  
  char *cur = NULL;
  char *prev = NULL;
  char *saveptr = NULL;
  prev = strtok_r(path, "/", &saveptr);
  cur = strtok_r(NULL, "/", &saveptr);
  while (cur != NULL){
    struct inode* inode;
    if(is_current(prev)){
      prev = cur;
      cur = strtok_r(NULL, "/", &saveptr);
      continue;
    }
    else if(is_prev(prev)){
      if (dir != NULL){
      inode = inode_open(inode_get_prev(dir_get_inode(dir)));
      }
      else {
        inode = NULL;
      }
      if (inode == NULL){
        return NULL;
      }
    }
    else if(dir_lookup(dir, prev, &inode) == false)
      return NULL;

    if(inode_is_file(inode))
    {
      inode_close(inode);
    }
    else {
      dir_close(dir);
      dir = dir_open(inode);
    }
    prev = cur;
    cur = strtok_r(NULL, "/", &saveptr);
  } 

  return dir;
}

bool
filesys_chdir(const char* name)
{
  struct dir* dir = name_to_dir(name);
  char* name2 = extract_name(name);
  if (name2 == NULL) return false;
  struct inode *inode = NULL;
  
  if (dir == NULL) 
  {
    free(name2);
    return false;
  }

  else if (is_prev(name2))
  {
    block_sector_t sector = inode_get_prev(dir_get_inode(dir));
    inode = inode_open(sector);
    if(inode == NULL)
    {
      free(name2);
      return false;
    }
  }
  else if (is_current(name2))
  {
    thread_current() -> cur_dir = dir;
    free(name2);
    return true;
  }
  else if (strlen(name2) == 0 && inode_get_inumber(dir_get_inode(dir)) == ROOT_DIR_SECTOR)
  {
    thread_current() -> cur_dir = dir;
    free(name2);
    return true;
  }
  else dir_lookup(dir, name2, &inode);
  dir_close(dir);
  dir = dir_open(inode);

  if(dir == NULL) 
  {
    free(name2);
    return false;
  }
  else
  {
    dir_close(thread_current() -> cur_dir);
    thread_current() -> cur_dir = dir;
    free(name2);
    return true;
  }
}

bool is_current(char *name){
  return (strcmp(name, ".")==0);
}

bool is_prev(char *name){
  return (strcmp(name, "..")==0);
}
