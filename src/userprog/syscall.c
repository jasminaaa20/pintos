#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include <user/syscall.h>
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
static void mem_stack(uint8_t *uaddr, uint8_t *kaddr, size_t size);
static int
get_user(const uint8_t *uaddr);
static bool
put_user(uint8_t *udst, uint8_t byte);
int sys_open(const char *filename);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_halt(void);
void sys_exit(int status);
int sys_wait(pid_t pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
void sys_close (int fd);
unsigned sys_tell (int fd);
int sys_read (int fd, void *buffer, unsigned length);
void sys_seek (int fd, unsigned position);
pid_t sys_exec (const char * file);
int sys_filesize (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_num;
  mem_stack(f->esp, &syscall_num, sizeof(syscall_num));

switch (syscall_num){
  case SYS_HALT:
  {
    sys_halt();
    NOT_REACHED();
    break;
  }
  case SYS_OPEN:
  {
    char *filename;
    mem_stack(f->esp + 4, &filename, sizeof(filename));
    f->eax=(uint32_t)sys_open(filename);
    break;
  }
  case SYS_CREATE:
  {
    int size;
    char *filename;
    mem_stack(f->esp + 4, &filename, sizeof(filename));
    mem_stack(f->esp + 8, &size, sizeof(size));
    f->eax=(uint32_t)sys_create(filename,size);
    break;
  }
  case SYS_EXIT:
  {
    int status;
    mem_stack(f->esp + 4, &status, sizeof(status));

    sys_exit(status);
    NOT_REACHED();
    break;

  }
  case SYS_EXEC:
  {
    char *filename;
    mem_stack(f->esp + 4, &filename, sizeof(filename));
    f->eax=(uint32_t)sys_exec(filename);
    break;
  }
  case SYS_CLOSE:
  {
    int fd;
    mem_stack(f->esp + 4, &fd, sizeof(fd));
    sys_close(fd);
    break;
  }

  case SYS_READ:
  {
    int fd;
    const void *buffer;
    unsigned size;

    mem_stack(f->esp + 4, &fd, sizeof(fd));
    mem_stack(f->esp + 8, &buffer, sizeof(buffer));
    mem_stack(f->esp + 12, &size, sizeof(size));

    f->eax = (int32_t) sys_read(fd, buffer, size);
    break;
  }
  case SYS_WAIT:
  {
    pid_t pid;
    mem_stack(f->esp + 4, &pid, sizeof(pid_t));

    f->eax = (uint32_t)sys_wait(pid);
    break;

  }

  case SYS_SEEK:
  {
    int size;
    unsigned position;
    mem_stack(f->esp + 4, &size, sizeof(size));
    mem_stack(f->esp + 8, &position, sizeof(position));
    sys_seek(size,position);
    break;
  }
  case SYS_WRITE:
  {
    int fd;
    const void *buffer;
    unsigned size;

    mem_stack(f->esp + 4, &fd, sizeof(fd));
    mem_stack(f->esp + 8, &buffer, sizeof(buffer));
    mem_stack(f->esp + 12, &size, sizeof(size));

    f->eax = (int32_t) sys_write(fd, buffer, size);
    break;

  }
  case SYS_FILESIZE:
  {
    int fd;
    mem_stack(f->esp + 4, &fd, sizeof(fd));

    f->eax = (int)sys_filesize(fd);
    break;
  }
  case SYS_REMOVE:
  {
    char *filename;
    mem_stack(f->esp + 4, &filename, sizeof(filename));
    f->eax=(bool)sys_remove(filename);
    break;
  }
  default:{
    printf ("system call not implemented!\n");
    thread_exit ();

  }

}
 
}


//................................SYSTEM CALL FUNCTIONS.......................................

//method for sys_halt
void sys_halt(void){
  shutdown_power_off();
}

//method fo sys_exit
void sys_exit(int status)
{
  struct thread *current = thread_current();
  if (status < 0)
    status = -1;  
  printf("%s: exit(%d)\n", current->name, status); 
  thread_exit();
}

//method for sys_open
int sys_open(const char *filename){
  struct file *opened_file;
  struct file_descriptor *f_desc;
  opened_file = filesys_open(filename);
  if (!opened_file){return -1;}

  f_desc = malloc(sizeof(struct file_descriptor));
  f_desc -> file = opened_file;
  struct list *files_list = &thread_current ()->file_details;

  if (list_empty(files_list)){
  f_desc ->id = 2;

  }else{
  f_desc -> id = (list_entry(list_back(files_list), struct file_descriptor, elem) -> id) +1;

  }
  list_push_back(files_list, &f_desc ->elem);

  return f_desc->id;
}

//method for sys_exec
pid_t sys_exec (const char * file)
{
  /* If a null file is passed in, then return -1. */
	if(!file)
		return -1;
  /* Get and return the PID of the process that is created. */
	pid_t child_tid = process_execute(file);
	return child_tid;
} 

//method for sys_seek
void sys_seek (int fd, unsigned position)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();

  /* If there are no files to seek through, then we immediately return. */
  if (list_empty(&t->file_details))
    return;

  /* Look to see if the given fd is in our list of file_details. IF so, then we
     seek through the appropriate file. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc= list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
      {
        file_seek(f_desc->file, position);
        return;
      }
  }
  /* If we can't seek, return. */
  return;
}

//method for sys_create
bool sys_create (const char *file, unsigned initial_size)
{

  bool file_status = filesys_create(file, initial_size);

  return file_status;
}

//method for sys_wait
int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

//method for sys_remove
bool sys_remove (const char *file)
{
  bool was_removed = filesys_remove(file);
  return was_removed;
}

//method for sys_close
void sys_close (int fd)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();


  /* If there are no files in our file_details list, then return */
  if (list_empty(&t->file_details))
    return;

  /* Look to see if the given fd is in our list of file_details. If so, then we
     close the file and remove it from our list of file_details. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc = list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
      {
        file_close(f_desc->file);
        list_remove(&f_desc->elem);
        return;
      }
  }

  return;
}

//method for sys_write
int sys_write (int fd, const void *buffer, unsigned length)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();
  if((uint8_t*)buffer+length-1>=PHYS_BASE ||get_user((uint8_t*)buffer)==-1|| get_user((uint8_t*)buffer+length-1)==-1)
    sys_exit(-1);

  /* If fd is equal to one, then we write to STDOUT (the console, usually). */
	if(fd == 1)
	{
		putbuf(buffer, length);
    return length;
	}
  /* Check to see if the given fd is open and owned by the current process. If so, return
     the number of bytes that were written to the file. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc = list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
      {
        int bytes_written = (int) file_write(f_desc->file, buffer, length);
        return bytes_written;
      }
  }


  /* If we can't write to the file, return 0. */
  return -1;
}

//method sys_read
int sys_read (int fd, void *buffer, unsigned length)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();

  if((uint8_t*)buffer+length-1>=PHYS_BASE ||get_user((uint8_t*)buffer)==-1|| get_user((uint8_t*)buffer+length-1)==-1)
    sys_exit(-1);
  /* If fd is one, then we must get keyboard input. */
  if (fd == 0)
  {
    return (int) input_getc();
  }

  /* We can't read from standard out, or from a file if we have none open. */
  if (fd == 1 || list_empty(&t->file_details))
  {
    return 0;
  }

  /* Look to see if the fd is in our list of file descriptors. If found,
     then we read from the file and return the number of bytes written. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc = list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
      {
        int bytes = (int) file_read(f_desc->file, buffer, length);
        return bytes;
      }
  }

  /* If we can't read from the file, return -1. */
  return -1;
}

//method for sys_filesize
int sys_filesize (int fd)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();


  /* If there are no files associated with this thread, Then return -1 */
  if (list_empty(&t->file_details))
    return -1;

  /* Check to see if the given fd is open and owned by the current process. If so, return
     the length of the file. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc = list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
        return (int) file_length(f_desc->file);
  }

  /*  if we cannot find the file. */
  return -1;
}

//method for sys_tell
unsigned sys_tell (int fd)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;
  struct thread *t=thread_current();


  /* If there are no files in our file_details list, return immediately, */
  if (list_empty(&t->file_details))
    return -1;

  /* Look to see if the given fd is in our list of file_details. If so, then we
     call file_tell() and return the position. */
  for (temp = list_front(&t->file_details); temp != NULL; temp = temp->next)
  {
      struct file_descriptor *f_desc = list_entry (temp, struct file_descriptor, elem);
      if (f_desc->id == fd)
      {
        unsigned position = (unsigned) file_tell(f_desc->file);
        return position;
      }
  }

  return -1;
}



/* Load consecutive `size` bytes from `uaddr` to `kaddr`
   page fault when failed.
   Used to get arguments to kernel space from stack of the user program.  */
static void mem_stack(uint8_t *uaddr, uint8_t *arg, size_t arg_size)
{
  int32_t byte;
  for (int i = 0; i < arg_size; i++)
  {
    byte = get_user(uaddr + i);
    if (byte == -1)
    {
      //to avoide memoy leaks
      printf("Failed to Acess Memory\n");
      thread_exit();
    }

    *(char *)(arg + i) = byte & 0xff;
  }
}


/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfaultoccurred.*/
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}
