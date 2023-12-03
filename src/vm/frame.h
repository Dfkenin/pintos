#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include <list.h>
#include "threads/malloc.h"
#include "vm/swap.h"
#include "threads/vaddr.h"



struct fte {
    int fid; //frame number
    void *kpage; //kernel virtual page
    void *upage; //user virtual page
    struct thread *t; //in this thread
    struct list_elem lru; //for LRU
};

void ft_init();
static int allocate_fid (void);
void *allocate_frame(enum palloc_flags flags, void *upage);
void *free_frame(void *kpage);
void evict_frame();

#endif /* vm/frame.h */