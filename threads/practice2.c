#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid (void);

static struct list sleep_list;
static int64_t next_wakeup;

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t)((t) != NULL && (t) -> magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
 
/* pintos-kaist/devices/timer.c */
/* timer_sleep 함수 */
void timer_sleep(int64_t ticks) {
    int64_t start = timer_ticks();

    while (timer_elapsed(start) < ticks)
    /* 현재 사용중인 CPU 다른 쓰레드에게 양보하고 ready_list로 이동 */
    thread_yield();
}

//  timer_sleep(ticks) 함수는 현재 쓰레드를 ticks 시간 동안 재우는 함수
// tick은 컴퓨터가 작동하면서 1ms에 1씩 증가하는 값

/* timer_elapsed 함수 */

// timer_elapsed(start) 함수는 timer_sleep이 호출된 시점에서 지난 시간을 tick 단위로 리턴하는 함수
// 이 함수의 리턴값이 timer_sleep의 인자 ticks의 값보다 작으면 thread_yield() 함수를 호출한다.
// thread_yield() 함수는 현재 쓰레드가 대기열에 있는 리소스 사용 권한을 다른 쓰레드에게 반환하고 대기열로 이동한다.

/* Sleep과 Wake up */

// 기존의 스케줄링 방식은 수면해야 하는 쓰레드들이 ready 상태로 대기 리스트에 추가됨
// 이러한 문제점을 해결하기 위한 핵심 아이디어는 block 상태로 전환하여
// 수면 리스트에 추가하여 깨야하는 시간에 ready 상태로 바꿔주는 것

// 반복문을 이용해 대기 상태로 두지 않으려면 쓰레드들의 수면 시간에 대한 정보를 가지고 있어야 한다.
// 수면 정보를 포함한 thread 구조체를 생성하여 추가

// 수면 쓰레드 리스트 sleep_list 구조체를 추가
// 가장 먼저 깨야할 쓰레드의 일어날 시각을 저장할 next_wakeup 변수를 구조체에 추가

// next_wakeup 변수를 관리하는 함수를 생성

/* pintos-kaist/thread/thread.c */

/* 다음 깨야할 쓰레드의 일어날 시각을 리턴 */
void update_next_wakeup(int64_t ticks) {
    /* next_wakeup이 깨워야 할 쓰레드의 tick 값들 중 가장 작은 tick으로 업데이트 */
    next_wakeup = (next_wakeup > ticks) ? ticks : next_wakeup;
}

/* 가장 먼저 깨야할 쓰레드의 일어날 시각을 리턴 */
int64_t get_next_wakeup(void) {
    return next_wakeup;
}

// 쓰레드를 재우는 thread_sleep() 함수를 구현
// 수면해야 할 쓰레드들을 sleep_list에 추가하고 block 상태로 전환
// 이 과정에서 인터럽트를 무시하고 함수를 실행할 수 있게 하기 위해서 intr_disable() 함수를 사용
// 마지막에 다시 set_intr_level(old_level) 함수를 설정하여 인터럽트를 받아들이도록 변경
// 현재 쓰레드가 idle 쓰레드이면 수면하지 않도록 설정 필요

// idle 쓰레드는 운영체제가 초기화되고 생성되는 ready_list에 첫번째로 추가되는 쓰레드
// idle 쓰레드는 CPU가 실행상태를 유지하기 위해 실행할 쓰레드가 필요하기 때문
// CPU의 전원을 껐다가 키는 데에 소모되는 전력을 절약하기 위해

/* pintos-kaist/thread/thread.c */

/* 현재 쓰레드의 ticks 시각까지 수면하도록 하는 함수 */
void thread_sleep(int64_t ticks) {
    struct thread *curr;

    /* 인터럽트를 일시적으로 제한하고 이전의 인터럽트 상태를 저장 */
    enum intr_level old_level;
    old_level = intr_disable();

    /* idle 쓰레드가 수면 쓰레드에 추가되지 않도록 함 */
    curr = current_thread();
    ASSERT(curr != idle_thread);

    /* next_wakeup 함수가 실행되어야 할 tick 값을 업데이트 */
    update_next_wakeup(curr -> wakeup_time = ticks);

    /* 현재 쓰레드를 수면 대기열 큐에 삽입한 후 스케줄 */
    list_push_back(&sleep_list, &curr -> elem);

    /* 현재 쓰레드를 블락 상태로 변경하고 다시 스케줄될 때까지 블락 상태로 대기 */
    thread_block();

    /* 인터럽트 제한을 멈추고 기존의 인터럽트 상태로 변경 */
    set_intr_level(old_level);
}

/* pintos-kaist/thread/thread.c */
void thread_wakeup(int64_t wakeup_time) {
    struct list_elem *e;
    int64_t next_wakeup;

    next_wakeup = INT64_MAX;
    e = list_begin(&sleep_list);

    while (e != list_end(&sleep_list)) {
        struct thread *t = list_entry(e, struct thread, elem);

        if (wakeup_time >= t -> wakeup_time) {
            e = list_remove(&t -> elem);
            thread_unblock(t);
        } else {
            e = list_next(e);
            update_next_wakeup(t -> wakeup_time);
        }
    }
}

// 새롭게 추가된 네 개의 함수를 컴파일러가 인식할 수 있도록 thread.h에 프로토타입을 선언

/* pintos-kaist/thread/thread.h */

int64_t get_next_wakeup(void);
void update_next_wakeup(int64_t ticks);
void thread_sleep(int64_t ticks);
void thread_wakeup(int64_t ticks);

// 반복문을 실행하며 대기하는 대신 thread_sleep 함수를 호출하도록 timer_sleep 함수를 변경

/* pintos-kaist/device/timer.c */
void timer_sleep(int64_t ticks) {
    int64_t start = timer_ticks();

    ASSERT (get_intr_level() == INTR_ON);

    /* 기존의 busy waiting을 유발하는 대기 상태 부분을 삭제하고
       sleep_list에 추가하는 thread_sleep() 함수를 호출 */
    thread_sleep(start + ticks);
}

/* pintos-kaist/device/timer.c */
static void timer_interrupt(struct interrupt_frame *args) {
    // ...
    /* 매 tick마다 수면 큐에서 깨울 쓰레드가 있는지 확인하고 thread_wakeup 함수를 호출 */
    if (get_next_wakeup() <= ticks) {
        thread_wakeup(ticks);
    }
}