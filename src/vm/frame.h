#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include <list.h>
#include "threads/malloc.h"
#include "vm/swap.h"



struct fte {
    int fid; //frame number
    void *kpage; //kernel virtual page
    void *upage; //user virtual page
    struct thread *t; //in this thread
    struct list_elem lru; //for LRU
};

void ft_init(void);
void *allocate_frame(enum palloc_flags flags, void *upage);
void *free_frame(void *kpage);
void evict_frame(void);

#endif /* vm/frame.h */