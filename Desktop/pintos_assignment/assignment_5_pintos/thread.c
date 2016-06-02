#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "devices/timer.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
Used to detect stack overflow.  See the big comment at the top
of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/*
List of processes in THREAD_READY state,
that is, processes that are ready to run
but not actually running.
*/
static struct list ready_list;

/*
List of all processes.
Processes are added to this list
when they are first scheduled
and removed when they exit.
*/
static struct list all_list;

/*
ADDED IN PINTOS ASSIGNMENT 2.

contains threads that are currently in the THREAD_BLOCKED state
because timer_sleep was called on them.
*/
static struct list sleeping_threads;

/* Idle thread. */
static struct thread* idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread* initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
{
  void* eip;             /* Return address. */
  thread_func* function; /* Function to call. */
  void* aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/*
If false (default), use round-robin scheduler.

If true, use multi-level feedback queue scheduler.

Controlled by kernel command-line option "-o mlfqs".
*/
bool thread_mlfqs;

static void kernel_thread(thread_func*, void* aux);

static void idle(void* aux UNUSED);
static struct thread* running_thread(void);
static struct thread* next_thread_to_run(void);
static void init_thread(struct thread*, const char* name, int priority);
static bool is_thread(struct thread* t);
static void* alloc_frame(struct thread*, size_t size);

/* ADDED IN PINTOS ASSIGNMENT 3. */
static void thread_update_priorities(void);
static void thread_update_priority(struct thread* t, int new_priority);
static void thread_update_recent_cpus(void);
static void thread_update_recent_cpu(struct thread* t, void* aux);
static void thread_update_load_avg(void);
static int num_of_ready_or_running_threads(void);
static int thread_calc_mlfqs_priority(struct thread* t);
/*
load avg, often known as the system load average,
estimates the average number of threads
ready to run over the past minute.

Initialized explicitly to 0 for clarity.
*/
static FPReal load_avg = 0;

static void schedule(void);

void thread_schedule_tail(struct thread* prev);
static tid_t allocate_tid(void);

/* ADDED IN PINTOS ASSIGNMENT 4 */
struct thread*
thread_find(tid_t thread_tid)
{
  struct list_elem* e;

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {

    struct thread* t = list_entry(e, struct thread, allelem);

    if (t->tid == thread_tid) {
      return t;
    }
  }

  return NULL;
}

struct child_data*
child_data_find(tid_t child_tid, struct thread* t)
{

  struct list_elem* e;

  for (e = list_begin(&t->children); e != list_end(&t->children);
       e = list_next(e)) {

    struct child_data* cd = list_entry(e, struct child_data, elem);
    if (cd->tid == child_tid) {
      return cd;
    }
  }

  return NULL;
}

/*
Called from init.c

Initializes the threading system
by transforming the code that's currently running into a thread.

This can't work in general
and it is possible in this case
only because loader.S was careful
to put the bottom of the stack at a page boundary.

Also initializes the run queue and the tid lock.

After calling this function,
be sure to initialize the page allocator
before trying to create any threads with thread_create().

It is not safe to call thread_current()
until this function finishes.
*/
void
thread_init(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);

  // Initializing lists
  list_init(&ready_list);
  list_init(&all_list);
  list_init(&sleeping_threads);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();

#ifdef USERPROG
  /* ADDED IN PINTOS ASSIGNMENT 4. */
  initial_thread->parent_thread = NULL;
  initial_thread->parent_waiting = false;
  initial_thread->exit_status = ERROR_EXIT_STATUS;
  list_init(&initial_thread->children);
  sema_init(&initial_thread->sema_child_wait, 0);

  /* ADDED IN PINTOS ASSIGNMENT 5. */
  sema_init(&initial_thread->sema_child_loaded, 0);
  initial_thread->child_loaded = false;

#endif
}

/*
Called from init.c

Starts preemptive thread scheduling by enabling interrupts.

Also creates the idle thread.
*/
void
thread_start(void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;

  // Initialize semaphore to 0
  sema_init(&idle_started, 0);

  //  thread name, thread priority, thread function, function argument (aux)
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/*
Called by the timer interrupt handler at each timer tick.

Thus, this function runs in an external interrupt context.
*/
void
thread_tick(void)
{
  struct thread* t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;

#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif

  else
    kernel_ticks++;

  /*
  ADDED IN PINTOS ASSIGNMENT 3

  thread_tick is called at each timer interrupt,
  where we increment the recent_cpu.

  Every second update:

  1. the recent_cpu of all ready and running threads
  2. the load_avg
  */
  if (thread_mlfqs) {
    FPR_INC(&t->recent_cpu);

    if (timer_ticks() % TIMER_FREQ == 0) {
      thread_update_recent_cpus();
      thread_update_load_avg();
    }

    if (timer_ticks() % 4 == 0) {
      thread_update_priorities();
    }
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();
}

/* Prints thread statistics. */
void
thread_print_stats(void)
{
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

/*
CHANGED IN PINTOS ASSIGNMENT 3, 4.

Creates a new KERNEL thread
named NAME with the given initial PRIORITY,
which executes FUNCTION passing AUX as the argument,
and adds it to the ready queue.

Returns the thread identifier for the new thread,
or TID_ERROR if creation fails.

If thread_start() has been called,
then the new thread
may be scheduled before thread_create() returns.

It could even exit before thread_create() returns.

Contrariwise, the original thread
may run for any amount of time
before the new thread is scheduled.

Use a semaphore or some other form of synchronization
if you need to ensure ordering.

The code provided
sets the new thread's `priority' member to PRIORITY,
but no actual priority scheduling is implemented.
Priority scheduling is the goal of Problem 1-3.
*/
tid_t
thread_create(const char* name, int priority, thread_func* function, void* aux)
{
  struct thread* t;

  // fake stack frames
  struct kernel_thread_frame* kf;
  struct switch_entry_frame* ef;
  struct switch_threads_frame* sf;

  tid_t tid;
  enum intr_level old_level;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);

  tid = t->tid = allocate_tid();

#ifdef USERPROG
  // ADDED IN PINTOS ASSIGNMENT 4.
  t->parent_thread = NULL;
  t->parent_waiting = false;
  t->exit_status = ERROR_EXIT_STATUS;
  sema_init(&t->sema_child_wait, 0);
  list_init(&t->children);

  // ADDED IN PINTOS ASSIGNMENT 5.
  t->child_loaded = false;
  sema_init(&t->sema_child_loaded, 0);

#endif

  /*
  Prepare thread for first run by initializing its stack.

  Do this atomically so intermediate values for the 'stack'
  member cannot be observed.
  */
  old_level = intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock(t);

  /* ADDED IN PINTOS ASSIGNMENT 3 */
  if (t->priority > thread_current()->priority) {
    thread_yield();
  }

  return tid;
}

/*
Puts the current thread to sleep.
It will not be scheduled again until awoken by thread_unblock().

This function must be called with interrupts turned off.
It is usually a better idea
to use one of the synchronization primitives in synch.h.
*/
void
thread_block(void)
{
  // Makes sure it's not an external interrupt
  ASSERT(!intr_context());

  // Make sure that interrupts are off
  ASSERT(intr_get_level() == INTR_OFF);

  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/*
Transitions a blocked thread T to the ready-to-run state.
This is an error if T is not blocked.

(Use thread_yield() to make the running thread ready.)

This function does not preempt the running thread.
This can be important:
if the caller had disabled interrupts itself,
it may expect that it can atomically unblock a thread
and update other data.
*/
void
thread_unblock(struct thread* t)
{
  enum intr_level old_level;
  ASSERT(is_thread(t));

  old_level = intr_disable();

  ASSERT(t->status == THREAD_BLOCKED);

  list_push_back(&ready_list, &t->elem);
  t->status = THREAD_READY;

  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char*
thread_name(void)
{
  return thread_current()->name;
}

/*
Returns the running thread.
This is running_thread()
plus a couple of sanity checks.
See the big comment at the top of thread.h for details.
*/
struct thread*
thread_current(void)
{
  struct thread* t = running_thread();

  /*
  Make sure T is really a thread.
  If either of these assertions fire, then your thread may
  have overflowed its stack.

  Each thread has less than 4 kB of stack,
  so a few big automatic arrays or moderate
  recursion can cause stack overflow.
  */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid(void)
{
  return thread_current()->tid;
}

/*
Deschedules the current thread and destroys it.

Never returns to the caller.
*/
void
thread_exit(void)
{
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /*
  Remove thread from all threads list,
  set our status to dying,
  and schedule another process.
  That process will destroy us
  when it calls thread_schedule_tail().
  */
  intr_disable();
  list_remove(&thread_current()->allelem);

  // All fields of this thread are going to become dummy!
  thread_current()->status = THREAD_DYING;

  schedule();
  NOT_REACHED();
}

/*
Yields the CPU.

The current thread is NOT put to sleep and
may be scheduled again immediately
at the scheduler's whim.
*/
void
thread_yield(void)
{
  struct thread* cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();

  if (cur != idle_thread) {
    list_push_back(&ready_list, &cur->elem);
  }

  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/*
Invoke function 'func' on all threads,
passing along 'aux'.

This function must be called with INTERRUPTS OFF.
*/
void
thread_foreach(thread_action_func* func, void* aux)
{
  struct list_elem* e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/*
ADDED IN PINTOS ASSIGNMENT 2.

Add t to the list of sleeping threads.
*/
void
make_sleep(struct thread* t)
{
  ASSERT(intr_get_level() == INTR_OFF);

  list_push_back(&sleeping_threads, &t->sleep_elem);
}

/*
ADDED IN PINTOS ASSIGNMENT 2.

Iterates through all sleeping threads,
and wakes up the ones that need to be waken up.
*/
void
try_to_wake_up_sleeping_threads(int64_t since_boot)
{
  ASSERT(intr_get_level() == INTR_OFF);

  struct list_elem* e;

  for (e = list_begin(&sleeping_threads); e != list_end(&sleeping_threads);
       e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, sleep_elem);

    if (since_boot >= t->waking_up_time) {
      list_remove(&t->sleep_elem);
      thread_unblock(t);
    }
  }
}

/*
IMPLEMENTED IN PINTOS ASSIGNMENT 3
*/
bool
thread_compare_priorities(const struct list_elem* a, const struct list_elem* b,
                          void* aux)
{
  struct thread* t1 = list_entry(a, struct thread, elem);
  struct thread* t2 = list_entry(b, struct thread, elem);
  return t1->priority < t2->priority;
}

/*
ADDED IN PINTOS ASSIGNMENT 3

Update priority of t with new_priority,
and eventually yield the CPU,
if the thread with the highest priority
isn't already running.
*/
static void
thread_update_priority(struct thread* t, int new_priority)
{
  t->priority = new_priority;

  // Yield eventually
  struct list_elem* max =
    list_max(&ready_list, thread_compare_priorities, NULL);
  struct thread* t_max = list_entry(max, struct thread, elem);

  if ((t_max->status != THREAD_RUNNING) && (t_max->priority > t->priority)) {
    thread_yield();
  }
}

/*
CHANGED IN PINTOS ASSIGNMENT 3.

Sets the current thread's priority to NEW_PRIORITY.
*/
void
thread_set_priority(int new_priority)
{
  thread_update_priority(thread_current(), new_priority);
}

/*
Returns the current thread's priority.
In the presence of priority donation,
returns the higher (donated) priority.
*/
int
thread_get_priority(void)
{
  return thread_current()->priority;
}

/*
IMPLEMENTED IN PINTOS ASSIGNMENT 3.

Sets the current thread's nice value to NICE,

and recalculate its priority based on that,

and yield if the new priority is not the highest anymore.
*/
void
thread_set_nice(int nice UNUSED)
{
  thread_current()->nice = nice;

  // Set the new priority of the current thread based on the new value of nice.
  // Yield the CPU if its priority is not the highest anymore.
  thread_set_priority(thread_calc_mlfqs_priority(thread_current()));
}

/*
IMPLEMENTED IN PINTOS ASSIGNMENT 3.

Returns the current thread's nice value.
*/
int
thread_get_nice(void)
{
  return FPR_TO_INT(thread_current()->nice);
}

/*
IMPLEMENTED IN PINTOS ASSIGNMENT 3.

Returns 100 times the system load average:

return load_avg * 100.
*/
int
thread_get_load_avg(void)
{
  return FPR_TO_INT(FPR_MUL_INT(load_avg, 100));
}

/*
IMPLEMENTED IN PINTOS ASSIGNMENT 3.

Returns 100 times the current thread's recent_cpu value.

return recent_cpu * 100
*/
int
thread_get_recent_cpu(void)
{
  return FPR_TO_INT(FPR_MUL_INT(thread_current()->recent_cpu, 100));
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Returns the new priority of t
based on its recent_cpu and nice values.
*/
static int
thread_calc_mlfqs_priority(struct thread* t)
{
  return PRI_MAX - FPR_TO_INT(FPR_DIV_INT(t->recent_cpu, 4)) - (t->nice * 2);
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Called by thread_foreach in thread_update_recent_cpus
to update the recent_cpu field of the thread pointed by t,
if that thread is ready or running.
*/
static void
thread_update_recent_cpu(struct thread* t, void* aux)
{
  if (t->status == THREAD_READY || t->status == THREAD_RUNNING) {
    FPReal* c = (FPReal*)aux;
    t->recent_cpu = FPR_ADD_INT(FPR_MUL_FPR(*c, t->recent_cpu), t->nice);
  }
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Called by timer_interrupt (in timer.c)
every second to update the recent_cpu of the current thread.

recent_cpu = (2 * load_avg) / (2 * load_avg + 1) * recent_cpu + nice
*/
static void
thread_update_recent_cpus(void)
{
  // (2 * load_avg)
  FPReal a = FPR_MUL_INT(load_avg, 2);

  // (2 * load_avg) / (2 * load_avg + 1)
  FPReal c = FPR_DIV_FPR(a, FPR_ADD_INT(a, 1));

  // Update the recent_cpu of all threads
  thread_foreach(thread_update_recent_cpu, &c);
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Returns the number of ready and running thread.
Called by thread_update_load_avg.
*/
static int
num_of_ready_or_running_threads(void)
{
  // number of ready and running threads
  int c = 0;

  struct list_elem* e;

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {

    struct thread* t = list_entry(e, struct thread, allelem);

    if (t != idle_thread &&
        (t->status == THREAD_RUNNING || t->status == THREAD_READY))
      ++c;
  }

  return c;
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Called every second to compute the following:
load_avg = (59/60)*load_avg + (1/60)*num_of_ready_or_running_threads()
*/
static void
thread_update_load_avg(void)
{
  // 59 * load_avg
  FPReal a = FPR_MUL_INT(load_avg, 59);

  int c = num_of_ready_or_running_threads();

  // 59*load_avg +  running_or_ready_threads
  load_avg = FPR_DIV_INT(FPR_ADD_INT(a, c), 60);
}

/*
ADDED IN PINTOS ASSIGNMENT 3.

Updates the priorities of all threads,
except the priority of the idle_thread.
*/
static void
thread_update_priorities(void)
{
  struct list_elem* e;

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, allelem);

    if (t != idle_thread) {
      t->priority = thread_calc_mlfqs_priority(t);
    }
  }
}

/*
Idle thread.
Executes when no other thread is ready to run.

The idle thread is initially put on
the ready list by thread_start().

It will be scheduled once initially,
at which point it initializes idle_thread,
"up"s the semaphore passed to it
to enable thread_start() to continue,
and immediately blocks.

After that, the idle thread never appears in the ready list.

It is returned by next_thread_to_run() as a
special case when the ready list is empty.
*/
static void
idle(void* idle_started_ UNUSED)
{
  struct semaphore* idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /*
    Re-enable interrupts and wait for the next one.

    The `sti' instruction disables interrupts until the
    completion of the next instruction, so these two
    instructions are executed atomically.  This atomicity is
    important; otherwise, an interrupt could be handled
    between re-enabling interrupts and waiting for the next
    one to occur, wasting as much as one clock tick worth of
    time.

    See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
    7.11.1 "HLT Instruction".
    */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func* function, void* aux)
{
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread*
running_thread(void)
{
  uint32_t* esp;

  /*
  Copy the CPU's stack pointer into `esp',
  and then round that down to the start of a page.

  Because `struct thread' is always at the beginning of a page
  and the stack pointer is somewhere in the middle,
  this locates the curent thread.
  */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/*
Returns true if T appears to point to a valid thread.
*/
static bool
is_thread(struct thread* t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/*
Does basic initialization of T
as a blocked thread named NAME.
*/
static void
init_thread(struct thread* t, const char* name, int priority)
{
  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t*)t + PGSIZE;

  /*
   ADDED IN PINTOS ASSIGNMENT 3.
   */
  if (thread_mlfqs) {
    t->recent_cpu = 0;
    t->nice = 0;
    t->priority = thread_calc_mlfqs_priority(t);
  } else {
    t->priority = priority;
  }

  t->magic = THREAD_MAGIC;
  list_push_back(&all_list, &t->allelem);
}

/*
Allocates a SIZE-byte frame
at the top of thread T's stack and
returns a pointer to the frame's base.
*/
static void*
alloc_frame(struct thread* t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/*
CHANGED IN PINTOS ASSIGNMENT 3.

Chooses and returns the next thread to be scheduled.

Should return a thread from the run queue,
unless the run queue is empty.

(If the running thread can continue running,
then it will be in the run queue.)

If the run queue is empty, return idle_thread.
*/
static struct thread*
next_thread_to_run(void)
{
  if (list_empty(&ready_list)) {
    return idle_thread;
  } else {

    // Returns the thread with the highest priority.
    struct list_elem* max_elem =
      list_max(&ready_list, thread_compare_priorities, NULL);

    struct thread* t = list_entry(max_elem, struct thread, elem);

    list_remove(max_elem);

    return t;
  }
}

/*
Completes a thread switch
by activating the new thread's page tables,
and, if the previous thread is dying, destroying it.

At this function's invocation,
we just switched from thread PREV,
the new thread is already running,
and interrupts are still disabled.

This function is normally invoked by thread_schedule()
as its final action before returning,
but the first time a thread is scheduled
it is called by switch_entry() (see switch.S).

It's not safe to call printf()
until the thread switch is complete.
In practice that means that printf()s should be
added at the end of the function.

After this function and its caller returns,
the thread switch is complete.
*/
void
thread_schedule_tail(struct thread* prev)
{
  struct thread* cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
#endif

  /*
  If the thread we switched from is dying,
  destroy its struct thread.

  This must happen late,
  so that thread_exit() doesn't pull out the rug under itself.

  (We don't free initial_thread
  because its memory was not obtained via palloc().)
  */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/*
Schedules a new process.

At entry, interrupts must be off and
the running process's state
must have been changed from running to some other state.

This function finds another thread to run and switches to it.

It's not safe to call printf()
until thread_schedule_tail() has completed.
*/
static void
schedule(void)
{
  struct thread* cur = running_thread();
  struct thread* next = next_thread_to_run();
  struct thread* prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next)
    prev = switch_threads(cur, next);

  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
