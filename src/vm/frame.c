#include "vm/frame.h"
#include "userprog/syscall.h"
#include "threads/synch.h"


static struct list ft;
static struct lock fid_lock;

void ft_init();
static int allocate_fid (void);
void *allocate_frame(enum palloc_flags flags, void *upage);
void *free_frame(void *kpage);


void ft_init(){
    list_init(&ft);
    lock_init(&fid_lock);
}

void *allocate_frame(enum palloc_flags flags, void *upage){
    struct frame *f;
    void *kpage;
    
    kpage = palloc_get_page(flags);
    if (kpage == NULL){
        evict_page();
        kpage = palloc_get_page(flags);
        if (kpage == NULL){
            return NULL;
        }
    }

    f = (struct frame*)malloc(sizeof(struct frame));
    f->fid = allocate_fid();
    f->kpage = kpage;
    f->upage = upage;
    f->t = thread_current();
    list_push_back(&ft, &f->lru);

    return f->kpage;
}

void *free_frame(void *kpage){
    struct frame *f;
    struct list_elem *e;
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)){
        if (kpage == list_entry(e, struct frame, list_elem)->kpage){
            break;
        }
    }
    if (e == list_end(&ft)){
        e = NULL;
        sys_exit(-1);
    }

    palloc_free_page(e->kpage);
    pagedir_clear_page(e->t->pagedir, e->upage);
    
    list_remove(&e->lru);
    free(e);
}

void evict_page(){

}

static int
allocate_fid (void) //from allocate_tid of thread.c
{
  static int next_fid = 1;
  int fid;

  lock_acquire (&fid_lock);
  fid = next_fid++;
  lock_release (&fid_lock);

  return fid;
}