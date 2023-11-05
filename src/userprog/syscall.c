#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//mod 2-1
#include "threads/vaddr.h"
//mod 2-2
#include "userprog/pagedir.h"
#include "threads/synch.h"
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
    case SYS_EXIT: validity(f->esp+4); exit((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_EXEC: validity(f->esp+4); 
      if (exec((const char *)*(uint32_t *)(f->esp+4)) == -1)
        exit(-1);
      break;
    case SYS_WAIT: validity(f->esp+4); f->eax = wait((pid_t)*(uint32_t *)(f->esp+4)); break;
    case SYS_CREATE: validity(f->esp+4); validity(f->esp+8); f->eax = create((const char *)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8)); break;
    case SYS_REMOVE: validity(f->esp+4); f->eax = remove((const char *)*(uint32_t *)(f->esp+4)); break;
    case SYS_OPEN: validity(f->esp+4); f->eax = open((const char *)*(uint32_t *)(f->esp+4)); break;
    case SYS_FILESIZE: validity(f->esp+4); f->eax = filesize((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_READ: validity(f->esp+4); validity(f->esp+8); validity(f->esp+12); f->eax = read((int)*(uint32_t *)(f->esp+4),(void *)*(uint32_t *)(f->esp+8),(unsigned)*(uint32_t *)(f->esp+12)); break;
    case SYS_WRITE: validity(f->esp+4); validity(f->esp+8); validity(f->esp+12); f->eax = write((int)*(uint32_t *)(f->esp+4),(const void *)*(uint32_t *)(f->esp+8),(unsigned)*(uint32_t *)(f->esp+12)); break;
    case SYS_SEEK: validity(f->esp+4); validity(f->esp+8); seek((int)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8)); break;
    case SYS_TELL: validity(f->esp+4); f->eax = tell((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_CLOSE: validity(f->esp+4); close((int)*(uint32_t *)(f->esp+4)); break;
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
  thread_exit();
}
pid_t exec(const char *cmd_line){
  pid_t pid = process_execute(cmd_line);
  if (pid == -1) //error
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
  validity(file); 
  struct file *file_ = filesys_open(file);
  if (file_ == NULL)
    return -1;
  struct thread *cur=thread_current();
  struct file **fdt=cur->fd_tab;
  while ((cur->fd_idx<BOUND) && fdt[cur->fd_idx])
    cur->fd_idx++;
  int fd;
  if (cur->fd_idx>BOUND)
    fd = -1;
  else{
    fdt[cur->fd_idx]=file;
    fd=cur->fd_idx;
  }
  if(fd==-1)
    file_close(file_);
  return fd;
}

int filesize(int fd) {
  struct thread* cur = thread_current();
  struct file* selected;
  if (fd < 0 || fd >= BOUND)
  {
    selected = NULL;
  }
  selected = cur->fd_tab[fd];
  if (selected == NULL)
  {
    exit(-1);
  }
  return file_length(selected);
}

int read(int fd, void* buffer, unsigned size) {
  validity(buffer);
  int num;
  struct thread *cur = thread_current();
  if (fd == 0){
    *(char *)buffer = input_getc();
    num = size;
  }
  else{
    if ( fd < 0 || fd >= BOUND)
      return -1;
    else{
      lock_acquire(&race_lock);
      num = file_read(cur->fd_tab[fd], buffer, size);
      lock_release(&race_lock);
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
  struct file *file_;
  if ( fd < 0 || fd > BOUND)
    file_ = NULL;
  else{
    file_ = cur->fd_tab[fd];
  }
  if (file_ <= 2)
    return;
}

unsigned tell(int fd) {
  struct thread *cur = thread_current();
  struct file *file_;
  if ( fd < 0 || fd > BOUND)
    file_ = NULL;
  else{
  file_ = cur->fd_tab[fd];
  }
  if(file_ <= 2)
    return;
  return file_tell(file_);
}

void close(int fd) {
    struct thread* cur = thread_current();
    struct file* selected;
    if (fd < 0 || fd >= BOUND)
    {
        selected = NULL;
    }
    selected = cur->fd_tab[fd];
}


void validity(const uint32_t *addr)
{
    struct thread* cur = thread_current();
    if (addr == NULL || !(is_user_vaddr(addr)) || pagedir_get_page(cur->pagedir, addr) == NULL)
    {
        exit(-1);
    }
}
