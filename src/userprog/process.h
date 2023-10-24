#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <user/syscall.h>
struct file_descriptor{
    int id;
    struct list_elem elem;
    struct file *file;
    struct thread * master;
};
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


/*process control block for storing process information*/
struct process_control_block
{
    pid_t pid; 
    const char * cmd_line; 

    struct list_elem elem;       
    struct thread *parent_thread;

    bool is_waiting;     
    bool has_exited;      
    int32_t exiting_code; 

    /* For synchronization */
    struct semaphore semaphore_wait;        
};

#endif /* userprog/process.h */
