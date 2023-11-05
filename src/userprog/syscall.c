#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//mod 2-1
#include "threads/vaddr.h"
//mod 2-2
#include "userprog/pagedir.h"
#define BOTTOM 0x08048000

static void syscall_handler (struct intr_frame *);
//mod 2-1
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
//mod 2-2
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void validity(const uint64_t *addr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();

  //mod 2-1
  //printf("esp: %x\n", f->esp);
  //printf("esp + 8: %x\n", f->esp + 8);
  //printf("value of it: %x\n", (int *)*(uint32_t *)(f->esp+8));
  //printf("it is argv, so argv[0] is : %x\n", *(int *)*(uint32_t *)(f->esp+8));
  //printf("edi: %x\n", f->edi);

  //hex_dump(f->esp, f->esp, PHYS_BASE - f->esp, true);

  if (!is_user_vaddr(f->esp) || (f->esp < BOTTOM)){
    exit(-1);
  }

  switch (*(uint32_t *)f->esp){
    case SYS_HALT: halt(); break;
    case SYS_EXIT: if (!is_user_vaddr(f->esp+4) || (f->esp+4 < BOTTOM)) exit(-1); exit((int)*(uint32_t *)(f->esp+4)); break;
    case SYS_EXEC: if (!is_user_vaddr(f->esp+4) || (f->esp+4 < BOTTOM)) exit(-1); 
      if (exec((const char *)*(uint32_t *)(f->esp+4)) == -1)
        exit(-1);
      break;
    case SYS_WAIT: if (!is_user_vaddr(f->esp+4) || (f->esp+4 < BOTTOM)) exit(-1); f->eax = wait((pid_t)*(uint32_t *)(f->esp+4)); break;
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

int write(int fd, const void* buffer, unsigned size) {
    int num;
    struct thread cur = thread_current();
    validity(buffer);
    lock_acquire(&race_lock);
    if (fd == 1) {
        putbuf(buffer, size);
        num = size;
    }
    else
    {
        if (fd < 0 || fd >= BOUND)
            num = -1;
        else {
            num = file_write(cur->fd_tab[fd], buffer, size);
        }
    }
    lock_release(&race_lock);
    return num;
}

void validity(const uint64_t *addr)
{
    struct thread* cur = thread_current();
    if (addr == NULL || !(is_user_vaddr(addr)) || pagedir_get_page(cur->pagedir, addr) == NULL)
    {
        exit(-1);
    }
}
