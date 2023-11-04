#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

//mod 2-1
typedef int pid_t;

void syscall_init (void);

//mod 2-1
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pit);


#endif /* userprog/syscall.h */
