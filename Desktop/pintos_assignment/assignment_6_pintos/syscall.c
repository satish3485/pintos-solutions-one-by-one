#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>       // imports system calls' numbers
#include "lib/user/syscall.h" // imports system calls' numbers
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"

/* IMPORTED IN PINTOS ASSIGNMENT 6. */
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/hash.h"

/* IMPORTED IN PINTOS ASSIGNMENT 6. */

static void syscall_handler(struct intr_frame* f);

/* ADDED IN PINTOS ASSIGNMENT 4. */
#define NUM_OF_SYSCALLS 20

#include "userprog/pagedir.h"
#include "userprog/process.h"

/* Specific handlers to specific system calls. */

/* ADDED IN PINTOS ASSIGNMENT 4. */
typedef void (*handler)(struct intr_frame* f);
/* Table that holds pointers to system calls' handlers. */
static handler table[NUM_OF_SYSCALLS];

static void syscall_exit_handler(struct intr_frame* f);
static void syscall_write_handler(struct intr_frame* f);

/* ADDED IN PINTOS ASSIGNMENT 5. */
static void syscall_exec_handler(struct intr_frame* f);
static void syscall_wait_handler(struct intr_frame* f);

/* ADDED IN PINTOS ASSIGNMENT 6. */
static void syscall_create_handler(struct intr_frame* f);
static void syscall_remove_handler(struct intr_frame* f);
static void syscall_open_handler(struct intr_frame* f);
static void syscall_close_handler(struct intr_frame* f);
static void syscall_seek_handler(struct intr_frame* f);
static void syscall_tell_handler(struct intr_frame* f);
static void syscall_filesize_handler(struct intr_frame* f);
static void syscall_read_handler(struct intr_frame* f);
static void syscall_halt_handler(struct intr_frame* f);
static void exit_process(int exit_status);

/*
File descriptor number 0 is reserved for STDIN_FILENO.
File descriptor number 1 is reserved fro STDOUT_FILENO.
*/
static int next_file_descriptor_num = 2;
struct file_descriptor
{
  int fd;
  struct file* f_ptr;
  struct hash_elem elem;
};

static struct hash file_descriptors;

static unsigned hash_func(const struct hash_elem* e, void* aux UNUSED);
static bool compare_func(const struct hash_elem* a, const struct hash_elem* b,
                         void* aux UNUSED);

struct lock g_lock;
/***********************************/

void
syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // null-initialize all pointers to handlers
  memset(table, 0, NUM_OF_SYSCALLS);

  /* ADDED IN PINTOS ASSIGNMENT 4.

   SYS_WRITE maybe be handled differently in PINTOS ASSIGNMENT 6.
   */
  table[SYS_EXIT] = syscall_exit_handler;   // exit a process
  table[SYS_WRITE] = syscall_write_handler; // write to a file or to the stdout

  /* ADDED IN PINTOS ASSIGNMENT 5. */
  table[SYS_WAIT] = syscall_wait_handler; // wait for child process to terminate
  table[SYS_EXEC] = syscall_exec_handler; // start a process

  /* ADDED IN PINTOS ASSIGNMENT 6. */
  /* All the following 8 system call handlers are related to the files. */
  table[SYS_CREATE] = syscall_create_handler;
  table[SYS_REMOVE] = syscall_remove_handler;
  table[SYS_OPEN] = syscall_open_handler;
  table[SYS_CLOSE] = syscall_close_handler;
  table[SYS_SEEK] = syscall_seek_handler;
  table[SYS_TELL] = syscall_tell_handler;
  table[SYS_FILESIZE] = syscall_filesize_handler;
  table[SYS_READ] = syscall_read_handler;

  table[SYS_HALT] = syscall_halt_handler;

  hash_init(&file_descriptors, hash_func, compare_func, NULL);

  lock_init(&g_lock);
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

/* ADDED IN PINTOS ASSIGNMENT 6. */
static void
syscall_create_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  const char* name = (const char*)*(stack_ptr + 1);

  /*
   Check if name is not NULL and it's a valid pointer.
   */
  if (name == NULL || !is_user_vaddr(name) ||
      pagedir_get_page(thread_current()->pagedir, (const void*)name) == NULL) {
    f->eax = 0;
    exit_process(-1);

  } else {

    unsigned initial_size = *(stack_ptr + 2);

    lock_acquire(&g_lock);
    f->eax = filesys_create(name, initial_size);
    lock_release(&g_lock);
  }
}

static void
syscall_remove_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  const char* name = (const char*)*(stack_ptr + 1);

  /*
   Check if name is not NULL and it's a valid pointer.
   */
  if (name == NULL || !is_user_vaddr(name) ||
      pagedir_get_page(thread_current()->pagedir, (const void*)name) == NULL) {
    f->eax = 0;
    exit_process(-1);

  } else {
    lock_acquire(&g_lock);
    f->eax = filesys_remove(name);
    lock_release(&g_lock);
  }
}

static unsigned
hash_func(const struct hash_elem* e, void* aux UNUSED)
{
  return hash_int((hash_entry(e, struct file_descriptor, elem))->fd);
}

static bool
compare_func(const struct hash_elem* a, const struct hash_elem* b,
             void* aux UNUSED)
{
  struct file_descriptor* fda = hash_entry(a, struct file_descriptor, elem);
  struct file_descriptor* fdb = hash_entry(b, struct file_descriptor, elem);
  return fda->fd < fdb->fd;
}

static void
syscall_open_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  const char* name = (const char*)*(stack_ptr + 1);

  /*
   Check if name is not NULL and it's a valid pointer.
   */
  if (name == NULL || !is_user_vaddr(name) ||
      pagedir_get_page(thread_current()->pagedir, (const void*)name) == NULL) {

    /* BAD POINTER */
    f->eax = -1;
    exit_process(-1);
    return;
  }

  lock_acquire(&g_lock);

  /* filesys_open returns a pointer to the opened file or NULL.*/
  struct file* f_ptr = filesys_open(name);

  if (f_ptr == NULL) {
    /* Return -1 if file could NOT be opened. */
    f->eax = -1;
    // exit_process(-1);
  } else {

    struct file_descriptor* file_d = malloc(sizeof(struct file_descriptor));

    /* storing the file descriptor number.*/
    file_d->fd = next_file_descriptor_num;

    /* Storing the pointer to the opened file.*/
    file_d->f_ptr = f_ptr;

    ++next_file_descriptor_num;

    /*
     * Inserting in the file_descpritors hash table the elem correspondnig to
     * the file descriptor just created.
     */
    hash_insert(&file_descriptors, &file_d->elem);

    /* Return the file descriptor number if file was opened SUCCESSFULLY. */
    f->eax = file_d->fd;
  }

  lock_release(&g_lock);
}

static void
syscall_close_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  int fd = *(stack_ptr + 1);

  lock_acquire(&g_lock);

  // We want to search for a struct file with file descriptor fd.
  struct file_descriptor file_d;
  file_d.fd = fd;
  struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

  if (e != NULL) {

    /* Converting found hash_elem to corresponding file_descritor. */
    struct file_descriptor* found_fd =
      hash_entry(e, struct file_descriptor, elem);

    file_close(found_fd->f_ptr);

    /*
     * Deleting from hash table file_descritors
     * the entry corresponding to this found_fd.
     */
    hash_delete(&file_descriptors, &found_fd->elem);

    /* Freeing memory allocated for file_descriptor in syscall_open_handler.*/
    free(found_fd);
  }

  lock_release(&g_lock);
}

static void
syscall_read_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  int fd = *(stack_ptr + 1);
  void* buffer = (void*)*(stack_ptr + 2);
  unsigned size = (unsigned)*(stack_ptr + 3);

  if (buffer == NULL || !is_user_vaddr(buffer) ||
      pagedir_get_page(thread_current()->pagedir, buffer) == NULL) {
    /* BAD POINTER */
    f->eax = -1;
    exit_process(-1);
    return;
  }

  /*
   if (fd == STDIN_FILENO) {
    return input_getc();
   } */

  lock_acquire(&g_lock);

  // We want to search for a struct file with file descriptor fd.
  struct file_descriptor file_d;
  file_d.fd = fd;
  struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

  if (e != NULL) {

    /* Converting found hash_elem to corresponding file_descritor. */
    struct file_descriptor* found_fd =
      hash_entry(e, struct file_descriptor, elem);

    if (found_fd == NULL) {
      f->eax = -1;
    } else {
      f->eax = file_read(found_fd->f_ptr, buffer, size);
    }
  } else {

    // file could not be read.
    f->eax = -1;
  }

  lock_release(&g_lock);
}

static void
syscall_seek_handler(struct intr_frame* f)
{
  // void file_seek(struct file* file, off_t new_pos)

  int* stack_ptr = (int*)f->esp;
  int fd = *(stack_ptr + 1);
  unsigned new_position = *(stack_ptr + 2);

  lock_acquire(&g_lock);

  // We want to search for a struct file with file descriptor fd.
  struct file_descriptor file_d;
  file_d.fd = fd;
  struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

  if (e != NULL) {
    /* Converting found hash_elem to corresponding file_descritor. */
    struct file_descriptor* found_fd =
      hash_entry(e, struct file_descriptor, elem);

    file_seek(found_fd->f_ptr, new_position);
  }

  lock_release(&g_lock);
}

static void
syscall_tell_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  int fd = *(stack_ptr + 1);

  lock_acquire(&g_lock);

  // We want to search for a struct file with file descriptor fd.
  struct file_descriptor file_d;
  file_d.fd = fd;
  struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

  if (e != NULL) {
    /* Converting found hash_elem to corresponding file_descritor. */
    struct file_descriptor* found_fd =
      hash_entry(e, struct file_descriptor, elem);

    f->eax = file_tell(found_fd->f_ptr);
  }

  lock_release(&g_lock);
}

static void
syscall_filesize_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  int fd = *(stack_ptr + 1);

  lock_acquire(&g_lock);

  // We want to search for a struct file with file descriptor fd.
  struct file_descriptor file_d;
  file_d.fd = fd;
  struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

  if (e != NULL) {
    /* Converting found hash_elem to corresponding file_descritor. */
    struct file_descriptor* found_fd =
      hash_entry(e, struct file_descriptor, elem);

    f->eax = file_length(found_fd->f_ptr);
  }

  lock_release(&g_lock);
}

static void
syscall_halt_handler(struct intr_frame* f)
{
  shutdown_power_off();
}

/* ADDED IN PINTOS ASSIGNMENT 5. */
static void
syscall_wait_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  tid_t child_tid = *(stack_ptr + 1);
  f->eax = process_wait(child_tid);
}

/* ADDED IN PINTOS ASSIGNMENT 5. */
static void
syscall_exec_handler(struct intr_frame* f)
{
  int* stack_ptr = (int*)f->esp;
  char* command = (char*)(*(stack_ptr + 1));

  if (command != NULL && is_user_vaddr(command) &&
      pagedir_get_page(thread_current()->pagedir, (const void*)command) !=
        NULL) {
    f->eax = process_execute(command);
  } else {
    f->eax = -1;
  }
}

static void
exit_process(int exit_status)
{
  struct thread* cur = thread_current();
  cur->exit_status = exit_status;

  struct child_data* cd = child_data_find(cur->tid, cur->parent_thread);
  ASSERT(cd != NULL);
  cd->exit_status = exit_status;

  thread_exit(); // calls also process_exit
}

/* ADDED IN PINTOS ASSIGNMENT 4. */
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

  exit_process(exit_status);
}

/*
ADDED IN PINTOS ASSIGNMENT 4.

MODIFIED IN PINTOS ASSIGNMENT 6.
*/
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
  int fd = *(stack_ptr + 1); // file descriptor
  int* buffer = *(stack_ptr + 2);
  unsigned size = (unsigned)(*(stack_ptr + 3));

  if (buffer == NULL || !is_user_vaddr(buffer) ||
      pagedir_get_page(thread_current()->pagedir, buffer) == NULL) {
    f->eax = 0;
    exit_process(-1);
    return;
  }

  // Write to console...
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->eax = size;

  } else {

    lock_acquire(&g_lock);

    // We want to search for a struct file with file descriptor fd.
    struct file_descriptor file_d;
    file_d.fd = fd;
    struct hash_elem* e = hash_find(&file_descriptors, &file_d.elem);

    if (e != NULL) {

      /* Converting found hash_elem to corresponding file_descritor. */
      struct file_descriptor* found_fd =
        hash_entry(e, struct file_descriptor, elem);

      f->eax = file_write(found_fd->f_ptr, buffer, size);

    } else {
      // Could NOT write to file.
      f->eax = 0;
    }

    lock_release(&g_lock);
  }
}