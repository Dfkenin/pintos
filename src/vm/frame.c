#include "vm/frame.h"
#include "userprog/syscall.h"


static struct list ft;
static struct lock fid_lock;
static struct list_elem *lru_pointer;

void ft_init();
static int allocate_fid (void);
void *allocate_frame(enum palloc_flags flags, void *upage);
void *free_frame(void *kpage);
void evict_frame();


void ft_init(){
    list_init(&ft);
    lock_init(&fid_lock);
}

void *allocate_frame(enum palloc_flags flags, void *upage){
    struct frame *f;
    void *kpage;
    
    kpage = palloc_get_page(flags);
    if (kpage == NULL){
        evict_frame();
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
        exit(-1);
    }

    palloc_free_page(e->kpage);
    pagedir_clear_page(e->t->pagedir, e->upage);
    
    list_remove(&e->lru);
    free(e);
}

void evict_frame(){
    struct list_elem *e;
    struct s_page *sp;

    e = lru_pointer;
    sp = list_entry(e, struct s_page, lru);
    if (pagedir_is_accessed(sp->t->pagedir, sp->upage)){
        pagedir_set_accessed(sp->t->pagedir, sp->upage, false);

        for (; e != lru_pointer; ){
            sp = list_entry(e, struct s_page, lru);
            if (pagedir_is_accessed(sp->t->pagedir, sp->upage)){
                pagedir_set_accessed(sp->t->pagedir, sp->upage, false);
            }
            else{
                break;
            }

            if (list_next(e) == list_end(&ft)){
                e = list_begin(&ft);
            }
            else{
                e = list_next(e);
            }
        }
    }

    sp->swap_index = swap_out(sp->kpage);

    free_frame(sp->kpage);
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