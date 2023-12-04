#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/signal.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
//mod 5
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
struct file* get_file_from_fd(int fd);
bool validate_read(void *p, int size);
bool validate_write(void *p, int size);
mid_t mmap(int fd, void *addr);
void munmap(mid_t mapping);
void exit(int status);

static void (*syscall_table[20])(struct intr_frame*) = {
  sys_halt,
  sys_exit,
  sys_exec,
  sys_wait,
  sys_create,
  sys_remove,
  sys_open,
  sys_filesize,
  sys_read,
  sys_write,
  sys_seek,
  sys_tell,
  sys_close,
  sys_mmap,
  sys_munmap
}; // syscall jmp table

/* Reads a byte at user virtual address UADDR.
  UADDR must be below PHYS_BASE.
  Returns the byte value if successful, -1 if a segfault
  occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
  UDST must be below PHYS_BASE.
  Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

struct file* get_file_from_fd(int fd) {

  struct list_elem *e;
  struct thread *t = thread_current();
  struct fd_elem *fd_elem;

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd == fd)
      return fd_elem->file_ptr;
  }
  return NULL;
}

bool validate_read(void *p, int size) {
  int i = 0;
  if(p >= PHYS_BASE || p + size >= PHYS_BASE) return false;
  for(i = 0; i < size; i++) {
    if(get_user(p + i) == -1)
      return false;
  }
  return true;
}

bool validate_write(void *p, int size) {
  int i = 0;
  if(p >= PHYS_BASE || p + size >= PHYS_BASE) return false;
  for(i = 0; i < size; i++) {
    if(put_user(p + i, 0) == false)
      return false;
  }
  return true;
}

void kill_process() {
  send_signal(-1, SIG_WAIT);
  printf ("%s: exit(%d)\n", thread_current()->name, -1);
  thread_exit();
}

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{ 
  int syscall_num = validate_read(f->esp, 4) ? *(int*)(f->esp) : -1;
  
  if(syscall_num < 0 || syscall_num >= 20) {
    kill_process();
  }

  //mod 4 for pt-grow-stk-sc
  thread_current()->esp = f->esp;
  
  printf("Syscall num : %d\n", syscall_num);
  (syscall_table[syscall_num])(f);
}

// void halt(void)
void sys_halt (struct intr_frame * f UNUSED) {
  shutdown_power_off();
}

// void exit(int status)
void sys_exit (struct intr_frame * f) {
  int status;
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  
  status = *(int*)(f->esp + 4);
  exit(status);
}

void exit(int status){
  send_signal(status, SIG_WAIT);
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();  
}

// pid_t exec(const char *cmd_line)
void sys_exec (struct intr_frame * f) {
  //printf("exec 0\n");
  char *cmd_line;
  pid_t pid;
  char *itr;
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  //printf("exec 1\n");
  
  cmd_line = *(char**)(f->esp + 4);
  itr = cmd_line;
  
  if(!validate_read((void*)cmd_line, 1)) kill_process();
  //printf("exec 2\n");
  
  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }
  //printf("exec 3\n");
  
  pid = process_execute(cmd_line);
  //printf("exec 4\n");
  f->eax = pid == -1 ? pid : get_signal(pid, SIG_EXEC);
  //printf("exec 5 with pid %d\n", pid);
}

// int wait (pid_t pid)
void sys_wait (struct intr_frame * f) {
  if(!validate_read(f->esp + 4, 4)) kill_process();
  
  pid_t pid = *(pid_t*)(f->esp + 4);
  //printf("file lock? : %d\n", lock_held_by_current_thread(&file_lock));
  f->eax = process_wait(pid);
}

//bool create (const char *file, unsigned initial_size)
void sys_create (struct intr_frame * f) {
  char *name;
  unsigned initial_size;
  char *itr;
  
  if(!validate_read(f->esp + 4, 8)) kill_process();
  
  name = *(char **)(f->esp + 4);
  initial_size = *(unsigned*)(f->esp + 8);
  itr = name;
  
  if(!validate_read((void*)name, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  f->eax = filesys_create(name, initial_size);
  if (need_acquire){
    lock_release(&file_lock);
  }
}

//bool remove (const char *file)
void sys_remove (struct intr_frame * f) {
  char *name;
  char *itr;
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  
  name = *(char **)(f->esp + 4);
  itr = name;
  
  if(!validate_read((void*)name, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }
  
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  f->eax = filesys_remove(name);
  if (need_acquire){
    lock_release(&file_lock);
  }
}

//int open (const char *file)
void sys_open (struct intr_frame * f) {
  char *name;
  char *itr;
  struct thread *t;
  struct file *file;
  struct list_elem *e;
  struct fd_elem *f_elem;
  struct fd_elem *fd_elem;
  //printf("open 0\n");
  
  if(!validate_read(f->esp + 4, 4)) kill_process();

  name = *(char **)(f->esp + 4);
  itr = name;
  //printf("open 1 the %s\n", name);

  if(!validate_read((void*)name, 1)) kill_process();
  //printf("open 2\n");

  while(*itr != '\0') {
    itr++;
    //if(!validate_read((void*)itr, 1)) kill_process();
  }
  //printf("open 3\n");
  
  if(itr == name) {
    f->eax = -1;
    return;
  }
  //printf("open 4\n");
  
  t = thread_current();
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  file = filesys_open(name); //if fails, it returns NULL
  f_elem = malloc(sizeof(struct fd_elem));
  //printf("open 5\n");
  
  if(file == NULL) {
    if (need_acquire){
      lock_release(&file_lock);
    }
    f->eax = -1;
    return;
  }
  //printf("open 6\n");

  f_elem->fd = 2;
  f_elem->file_ptr = file;
  
  if (need_acquire){
    lock_release(&file_lock);
  }

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd > f_elem->fd) {
      e = list_prev(e);
      list_insert(e, &f_elem->elem);
      f->eax = f_elem->fd;
      return;
    }
    f_elem->fd++;
  }
  list_push_back(&t->fd_table, &f_elem->elem);
  f->eax = f_elem->fd;
  //printf("open 7\n");
}

//int filesize (int fd)
void sys_filesize (struct intr_frame * f) {
  int fd;
  struct file *file;
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  
  fd = *(int*)(f->esp + 4);
  file = get_file_from_fd(fd);
  
  if(file == NULL) f->eax = -1;
  
  f->eax = file_length(file);
}

//int read (int fd, void *buffer, unsigned size)
void sys_read (struct intr_frame * f) {
  //printf("read entered.\n");
  char c;
  unsigned count = 0;
  int fd;
  uint8_t* buffer;
  unsigned size;
  struct file *file;
  
  if(!validate_read(f->esp + 4, 12)) kill_process();
  //printf("read 1.\n");
  
  fd = *(int*)(f->esp + 4);
  buffer = *(uint8_t**)(f->esp + 8);
  size = *(unsigned*)(f->esp + 12);
  //printf("read 2.\n");
  file = get_file_from_fd(fd); 
  //printf("read 3.\n");
  
  if(!validate_write(buffer, size)) kill_process();

  //printf("fd is %d\n", fd);
  
  if(fd == 0) {
    c = input_getc();
    while(c != '\n' && c != -1 && count < size) {
      if(!put_user(buffer, c)) kill_process();
      buffer++;
      count++;
      c = input_getc();
    }
    f->eax = count;
  }
  else if(fd == 1) {
    f->eax = -1;
  }
  else {
    if(file == NULL) {
      //printf("NULL file\n");
      f->eax = -1;
      return;
    }
    bool need_acquire = !lock_held_by_current_thread(&file_lock);
    if (need_acquire){
      lock_acquire(&file_lock);
    }
    f->eax = file_read(file, buffer, size);
    if (need_acquire){
      lock_release(&file_lock);
    }
    //printf("read end with %d\n", f->eax);
  }
}

//int write (int fd, const void *buffer, unsigned size)
void sys_write (struct intr_frame * f) {
  int fd;
  char* buffer;
  unsigned size;
  struct file *file;
  
  if(!validate_read(f->esp + 4, 12)) kill_process();
  
  fd = *(int*)(f->esp + 4);
  buffer = *(char**)(f->esp + 8);
  size = *(unsigned*)(f->esp + 12);
  file = get_file_from_fd(fd);
  
  if(!validate_read(buffer, size)) kill_process();
  
  if(fd == 0) {
    f->eax = 0; 
  }
  else if(fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  }
  else {
    if(file == NULL) {
      f->eax = 0;
      return;
    }
    bool need_acquire = !lock_held_by_current_thread(&file_lock);
    if (need_acquire){
      lock_acquire(&file_lock);
    }
    f->eax = file_write (file, buffer, size);
    if (need_acquire){
      lock_release(&file_lock);
    }
  }
}

//void seek (int fd, unsigned position)
void sys_seek (struct intr_frame * f) {
  int fd;
  off_t position;
  struct file *file;
  
  if(!validate_read(f->esp + 4, 8)) kill_process();
  
  fd = *(int*)(f->esp + 4);
  position = *(int*)(f->esp + 8);
  file = get_file_from_fd(fd);  
  
  if(file == NULL) f->eax = -1;
  
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  file_seek(file, position);
  if (need_acquire){
    lock_release(&file_lock);
  }
}

//unsigned tell (int fd)
void sys_tell (struct intr_frame * f) {
  if(!validate_read(f->esp + 4, 4)) kill_process();
  int fd = *(int*)(f->esp + 4);
  struct file *file = get_file_from_fd(fd);
  if(file == NULL)
    f->eax = -1;
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  f->eax = file_tell(file);
  if (need_acquire){
    lock_release(&file_lock);
  }
}

//void close (int fd)
void sys_close (struct intr_frame * f) {
  int fd;
  struct file *file;
  struct thread *t;
  struct list_elem *e;
  struct fd_elem *fd_elem;
  printf("close 0\n");
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  printf("close 1\n");
  
  fd = *(int*)(f->esp + 4);
  file = get_file_from_fd(fd);
  printf("close 2\n");
  t = thread_current();
    
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  file_close(file);
  if (need_acquire){
    lock_release(&file_lock);
  }
  printf("close 3\n");
  
  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd == fd) {
      printf("close 4\n");
      list_remove(e);
      free(fd_elem);
      printf("close 5\n");
      return;
    }
  }
}

//mod 5
void sys_mmap(struct intr_frame * f){
  int fd;
  void *addr;
  if(!validate_read(f->esp + 4, 8)) kill_process();
  
  fd = *(int*)(f->esp + 4);
  addr = *(void**)(f->esp + 8);
  printf("mmap 0 with %d, %p\n", fd, addr);
  f->eax = mmap(fd, addr);
}

mid_t mmap(int fd, void *addr){
  struct file *file;
  struct file *open;
  struct thread *t;
  int size;
  off_t ofs;
  struct memmap *memmap;
  uint32_t read_bytes;
  
  file = get_file_from_fd(fd);  
  printf("mmap 1\n");

  t = thread_current();
  size = file_length(file);

  if (!file || !addr || (int)addr%PGSIZE!=0){
    return -1;
  }
  printf("mmap 2\n");
  for (ofs = 0; ofs < size; ofs += PGSIZE){
    if (get_s_page(&t->s_pt, addr + ofs)){
      return -1;
    }
  }
  printf("mmap 3\n");

  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  open = file_reopen(file);
  if (!open){
    if (need_acquire){
      lock_release(&file_lock);
    }
    printf("mmap 4\n");
    return -1;
  }

  memmap = (struct memmap*)malloc(sizeof(struct memmap));
  memmap->mid = allocate_mid(t);
  memmap->file = open;
  memmap->addr = addr; // for munmap
  list_push_back(&t->memmap_table, &memmap->elem);
  printf("mmap 5\n");

  for (ofs = 0; ofs < size; ){
    read_bytes = ofs + PGSIZE < size ? PGSIZE : size - ofs;
    allocate_s_page(&t->s_pt, addr, file, ofs, read_bytes, PGSIZE - read_bytes, true, 0);
    
    ofs += PGSIZE; addr += PGSIZE;
  }

  if (need_acquire){
    lock_release(&file_lock);
  }
  printf("mmap 6\n");
  return memmap->mid;
}

void sys_munmap(struct intr_frame * f){
  mid_t mapping;
  printf("munmap 0\n");
  
  if(!validate_read(f->esp + 4, 4)) kill_process();
  
  mapping = *(mid_t*)(f->esp + 4);
  printf("munmap 1 with mid %d\n", mapping);

  munmap(mapping);
}

void munmap(mid_t mapping){
  void *addr;
  struct thread *t;
  int size;
  off_t ofs;
  struct memmap *memmap;
  struct list_elem *e;
  printf("munmap 2\n");

  t = thread_current();
  for (e = list_begin(&t->memmap_table); e != list_end(&t->memmap_table); e = list_next(e)){
    memmap = list_entry(e, struct memmap, elem);
    if (memmap->mid == mapping){
      break;
    }
  }
  if (e == list_end(&t->memmap_table)){
    printf("munmap 3\n");
    return;
  }
  printf("munmap 4\n");
  
  bool need_acquire = !lock_held_by_current_thread(&file_lock);
  if (need_acquire){
    lock_acquire(&file_lock);
  }
  size = file_length(memmap->file);
  addr = memmap->addr;
  printf("munmap 5\n");

  for (ofs = 0; ofs < size; ){
    struct s_page *cur_page = get_s_page(&t->s_pt, addr);
    if (pagedir_is_dirty(t->pagedir, addr)){
      file_write_at(cur_page->file, addr, cur_page->read_bytes, cur_page->ofs);
    }
    s_page_delete(&t->s_pt, cur_page);

    ofs += PGSIZE; addr += PGSIZE;
  }
  printf("munmap 6\n");
  if (need_acquire){
    lock_release(&file_lock);
  }

  list_remove(e);
}