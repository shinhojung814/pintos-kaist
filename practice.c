/* Semaphores */
struct semaphore sema;

/* Thread A */
void threadA(void) {
    sema_down (&sema);
}

/* Thread B */
void threadB(void) {
    sema_up(&sema);
}

/* main function */
void main(void) {
    sema_init(&sema, 0);
    thread_create("threadA", PRI_MIN, threadA, NULL);
    thread_create("threadB", PRI_MIN, threadB, NULL);
}

/* Represents a semaphore */
struct semaphore;

/* Initializes sema as a new semaphore with the given initial value */
void sema_init(struct semaphore *sema, unsigned value);

/* Executes the "down" or "P" operation on sema, waiting for
its value to become positive and then decrementing it by one. */
void sema_down(struct semaphore *sema);

/* Tries to execute the "down" or "P" operation on sema, without waiting */
/* returns true if sema was successfully decremented */
/* returns false if it was already zero and could not be decremented */
bool sema_try_down(struct semaphore *sema);

/* Executes the "up" or "V" operation on sema, incrementing its value */
void sema_up(struct semaphore *sema);

/* Locks */

struct lock;

void lock_init(struct lock *lock);

void lock_acquire(struct lock *lock);

bool lock_try_acquire(struct lock *lock);

void lock_release(struct lock *lock);

bool lock_held_by_current_thread(const struct lock *lock);

/* Monitors */

struct condition;

void cond_init;

void cond_wait(struct condition *cond, struct lock *lock);

void cond_signal(struct condition *cond, struct lock *lock);

void cond_broadcast(struct condition *cond, struct lock *lock);

#include "csapp.h"

/* Buffer */
char buf[BUF_SIZE];
/* Number of characters in buffer */
size_t n = 0;
/* Buffer index of next character to write */
size_t head = 0;
/* Buffer index of next character to read */
size_t tail = 0;
/* Monitor lock */
struct lock lock;
/* Signaled when the buffer is not empty */
struct condition not_empty;
/* Signaled when the buffer is not full */
struct condition not_full;

/* Initialize the locks and condition variables */
void put(char ch) {
    lock_acquire (&lock);

    /* Cannot add to buffer as long as the buffer is full */
    while (n == BUF_SIZE)
        cond_wait(&not_full, &lock);
    
    /* Add ch to buffer */
    ch = buf[head++ % BUF_SIZE];
    n++;

    /* Buffer cannot be empty anymore */
    cond_signal(&not_empty, &lock);
    lock_release(&lock);
}

char get(void) {
    char ch;
    
    lock_acquire(&lock);

    /* Cannot read buffer as long as the buffer empty */
    while (n == 0)
        cond_wait(&not_empty, &lock);
    
    /* Get ch from buffer */
    ch = buf[tail++ % BUF_SIZE];
    n--;

    /* Buffer cannot be full anymore */
    cond_signal(&not_full, &lock);
    lock_release(&lock);
}