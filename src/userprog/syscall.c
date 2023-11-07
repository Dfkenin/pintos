#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//mod 2-1
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
//mod 2-2
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#define BOTTOM 0x08048000

static void syscall_handler (struct intr_frame *);
//mod 2-1
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
//mod 2-2
struct lock race_lock;

bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void validity(const uint32_t *addr);
void for_valid(const uint32_t *addr, int num);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  //mod 2-2
  lock_init(&race_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();

  //mod 2-1
  //printf("switch: %d\n", *(uint32_t *)f->esp);
  //printf("esp + 8: %x\n", f->esp + 8);
  //printf("value of it: %x\n", (int *)*(uint32_t *)(f->esp+8));
  //printf("it is argv, so argv[0] is : %x\n", *(int *)*(uint32_t *)(f->esp+8));
  //printf("edi: %x\n", f->edi);

  //hex_dump(f->esp, f->esp, PHYS_BASE - f->esp, true);

  validity(f->esp); 

  switch (*(uint32_t *)f->esp){
    case SYS_HALT: halt(); break;
    case SYS_EXIT: for_valid(f->esp+4, 1); exit((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_EXEC: for_valid(f->esp+4, 1); f->eax = exec((const char *)*(uint32_t *)(f->esp+4)); break;
    case SYS_WAIT: for_valid(f->esp+4, 1); f->eax = wait((pid_t)*(uint32_t *)(f->esp+4)); break;
    case SYS_CREATE: for_valid(f->esp+4, 2); f->eax = create((const char *)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8)); break;
    case SYS_REMOVE: for_valid(f->esp+4, 1); f->eax = remove((const char *)*(uint32_t *)(f->esp+4)); break;
    case SYS_OPEN: for_valid(f->esp+4, 1); f->eax = open((const char *)*(uint32_t *)(f->esp+4)); break;
    case SYS_FILESIZE: for_valid(f->esp+4, 1); f->eax = filesize((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_READ: for_valid(f->esp+4, 3); f->eax = read((int)*(uint32_t *)(f->esp+4),(void *)*(uint32_t *)(f->esp+8),(unsigned)*(uint32_t *)(f->esp+12)); break;
    case SYS_WRITE: for_valid(f->esp+4, 3); f->eax = write((int)*(uint32_t *)(f->esp+4),(const void *)*(uint32_t *)(f->esp+8),(unsigned)*(uint32_t *)(f->esp+12)); break;
    case SYS_SEEK: for_valid(f->esp+4, 2); seek((int)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8)); break;
    case SYS_TELL: for_valid(f->esp+4, 1); f->eax = tell((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_CLOSE: for_valid(f->esp+4, 1); close((int)*(uint32_t *)(f->esp+4)); break;
    default: exit(-1); break;
  }
}


//mod 2-1
void halt(void){
  shutdown_power_off();
}
void exit(int status){
  struct thread *t = thread_current();
  t->exit_code = status;
  t->exit_called = true;
  printf("%s: exit(%d)\n", t->name, status);
  for (int i = 2; i < 128; ++i){
    if (thread_current()->fd_tab[i] != NULL)
      close(i);
  }
  thread_exit();
}
pid_t exec(const char *cmd_line){
  pid_t pid = process_execute(cmd_line);

  struct thread *t = thread_current();
  struct list_elem *e = NULL;

  struct list *children_list = &(t->children);  
  struct thread *child = NULL;
  for (e = list_begin (children_list); e != list_end (children_list);
       e = list_next (e))
    {
      child = list_entry (e, struct thread, childelem);
      //printf("%d while given %d\n", child->tid, child_tid);
      if (child->tid == pid){
        break;
      }
    }

  sema_down(&(child->load));
  
  if (pid == -1 || !child->loaded) //error
    return -1;
  
  return pid;
}
int wait(pid_t pid){
  return process_wait(pid);
}

//mod 2-2
bool create(const char* file, unsigned initial_size) {
  validity(file);
  return filesys_create(file, initial_size);
}

bool remove(const char* file) {
  validity(file);
  return filesys_remove(file);
}

int open(const char* file) {
  //printf("o1\n");
  validity(file); 
  //printf("o2\n");
  lock_acquire(&race_lock);
  struct file *file_ = filesys_open(file);
  //printf("o3\n");
  if (file_ == NULL){
    lock_release(&race_lock);
    return -1;
  }
  //printf("o4\n");
  struct thread *cur = thread_current();
  /* What are these codes for?
  printf("o5\n");
  while ((cur->fd_idx<BOUND) && fdt[cur->fd_idx])
    cur->fd_idx++;
  printf("o6\n");
  int fd;
  if (cur->fd_idx>BOUND)
    fd = -1;
  else{
    fdt[cur->fd_idx]=file;
    fd=cur->fd_idx;
  }
  printf("fd = %d\n", fd);
  if(fd==-1)
    file_close(file_);
  printf("o7\n");
  */
  //printf("o5\n");
  int fd = cur->fd_idx;
  cur->fd_tab[fd] = file_;
  ++(cur->fd_idx);
  lock_release(&race_lock);
  //printf("o6\n");
  return fd;
}

int filesize(int fd) {
  //printf("fs1\n");
  struct thread* cur = thread_current();
  struct file* selected;
  /*
  if (fd < 0 || fd >= BOUND){
    selected = NULL;
  }
  else{
    selected = cur->fd_tab[fd];
  }
  */
  selected = cur->fd_tab[fd];
  //printf("fs2 with fd : %d\n", fd);
  if (selected == NULL)
  {
    //printf("fs3-1\n");
    exit(-1);
  }
  //printf("fs3-2\n");
  int ret = file_length(selected);
  //printf("fs4\n");
  return ret;
}

int read(int fd, void* buffer, unsigned size) {
  //printf("r1\n");
  validity(buffer);
  int num;
  struct thread *cur = thread_current();
  struct file *file_;
  lock_acquire(&race_lock);
  //printf("r2. fd is %d\n", fd);
  if (fd == 0){
    for (int i = 0; i < size; ++i){
      ((char *) buffer)[i] = input_getc();
      if (((char *) buffer)[i] == '\0')
        break;
    }
    lock_release(&race_lock);
    num = size;
    //printf("r3-1\n");
  }
  else{
    if ( fd < 0 || fd >= BOUND){
      lock_release(&race_lock);
      //printf("r3-2\n");
      exit(-1);
    }
    else{
      //printf("r3-3-1 with fd : %d\n", fd);
      file_ = cur->fd_tab[fd];
      //printf("r3-3-2\n");
      if (file_ == NULL){
        lock_release(&race_lock);
        //printf("r3-3-3\n");
        exit(-1);
      }
      //printf("r3-3-4\n");
      num = file_read(file_, buffer, size);
      lock_release(&race_lock);
      //printf("r3-3-5\n");
    }
  }
  return num;
}

int write(int fd, const void* buffer, unsigned size) {
  int num;
  struct thread *cur = thread_current();
  //printf("w1\n");
  validity(buffer);
  //printf("w2\n");
  //printf("fd = %d\n", fd);
  if (fd == 1){
    lock_acquire(&race_lock);
    //printf("w3-1\n");
    putbuf(buffer, size);
    num = size;
  }
  else{
    if (fd < 0 || fd >= BOUND) {
      //printf("w3-2\n");
      exit(-1);
    }
    else {
      struct file *file_ = cur->fd_tab[fd];
      //printf("w3-2\n");
      if (file_ == NULL) exit(-1);
      //printf("w3-4\n");
      lock_acquire(&race_lock);
      num = file_write(file_, buffer, size);
    }
  }
  //printf("w4\n");
  lock_release(&race_lock);
  //printf("w5\n");
  return num;
}

void seek(int fd, unsigned position) {
  struct thread *cur=thread_current();
  struct file *file_ = cur->fd_tab[fd];
  if (file_)
    file_seek(file_, position);
}

unsigned tell(int fd) {
  struct thread *cur = thread_current();
  struct file *file_;
  if ( fd <= 1 || fd > BOUND)
    file_ = NULL;
  else{
    file_ = cur->fd_tab[fd];
  }
  if(file_)
    return file_tell(file_);
  return -1;
}

void close(int fd) {
  struct thread* cur = thread_current();
  struct file* file_;
  if (fd <= 1 || fd >= BOUND)
  {
    file_ = NULL;
  }
  else{
    file_ = cur->fd_tab[fd];
  }
  if (file_) {
    file_close(file_);
    cur->fd_tab[fd] = NULL;
  }
  else {
    exit(-1);
  }
}


void validity(const uint32_t *addr){
  struct thread* cur = thread_current();
  if (addr == NULL || !(is_user_vaddr(addr)) || addr < BOTTOM || pagedir_get_page(cur->pagedir, addr) == NULL)
  {
    exit(-1);
  }
}

void for_valid(const uint32_t *addr, int num){
  for (int i = 0; i < num; ++i){
    validity(addr + 4*i);
    validity(addr + 4*i + 1);
    validity(addr + 4*i + 2);
    validity(addr + 4*i + 3);
  }
}
