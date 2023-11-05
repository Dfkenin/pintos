#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//mod 2-1
#include "threads/vaddr.h"
#define BOTTOM 0x08048000

static void syscall_handler (struct intr_frame *);
//mod 2-1
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);

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
  if (!is_user_vaddr(f->esp) || (f->esp < BOTTOM)){
    exit(-1);
  }

  switch (f->eax){
    case SYS_HALT: halt(); break;
    case SYS_EXIT: exit((int)*(uint32_t *)(f->edi)); break;
    case SYS_EXEC: 
      if (exec((const char *)*(uint32_t *)(f->edi)) == -1)
        exit(-1);
      break;
    case SYS_WAIT: f->eax = wait((pid_t)*(uint32_t *)(f->edi)); break;
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
