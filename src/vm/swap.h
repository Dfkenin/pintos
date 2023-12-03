#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"


void swap_table_init(void);
size_t swap_out(void *kpage);
void swap_in(size_t index, void *kpage);

#endif /* vm/swap.h */