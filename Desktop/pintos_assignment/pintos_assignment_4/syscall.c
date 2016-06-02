#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h> // imports system calls' numbers
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>

static void syscall_handler(struct intr_frame* f);

/* ADDED IN PINTOS ASSIGNMENT 4. */
#define NUM_OF_SYSCALLS 20

#include "userprog/pagedir.h"
#include "userprog/process.h"

/* Specific handlers to specific system calls. */ static void
syscall_exit_handler(struct intr_frame* f);
static void syscall_write_handler(struct intr_frame* f);

typedef void (*handler)(struct intr_frame* f);
/* Table that holds pointers to system calls' handlers. */
static handler table[NUM_OF_SYSCALLS];

void
syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // null-initialize all pointers to handlers
  memset(table, 0, NUM_OF_SYSCALLS);

  table[SYS_EXIT] = syscall_exit_handler;
  table[SYS_WRITE] = syscall_write_handler;
}

static void
syscall_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;

  /*
   System call number is pushed to the top of the stack
   as last argument when a system call is generated.
   */
  int syscall_number = *stack_ptr;

  table[syscall_number](f);
}

static void
syscall_exit_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;

  /*
   Arguments pushed to the stack by SYSCALL1,
   which is called by EXIT in lib/user/syscall.c.

   pushl %[arg0]; -> exit status
   pushl %[number]; -> syscall number
   */
  int exit_status = *(stack_ptr + 1);
  struct thread* cur = thread_current();
  cur->exit_status = exit_status;

  thread_exit(); // calls also process_exit
}

static void
syscall_write_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;

  /*
   Arguments pushed to the stack by SYSCALL3,
   which is called by WRITE in lib/user/syscall.c.

   pushl %[arg2]; -> size
   pushl %[arg1]; -> buffer
   pushl %[arg0]; -> fd
   pushl %[number]; -> syscall number
   */
  int fd = *(stack_ptr + 1);
  int buffer = *(stack_ptr + 2);
  unsigned size = (unsigned)(*(stack_ptr + 3));

  if (fd == STDOUT_FILENO) {
    putbuf((const void*)buffer, size);
    f->eax = size;
  }
}