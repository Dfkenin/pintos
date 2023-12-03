#include "vm/frame.h"
#include "userprog/syscall.h"
#include "vm/page.h"


static struct list ft;
static struct lock fid_lock;
static struct list_elem *lru_pointer;

static int allocate_fid (void);
void evict_frame(void);

/*
void ft_init(void);
void *allocate_frame(enum palloc_flags flags, void *upage);
void *free_frame(void *kpage);
*/

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
        f = list_entry(e, struct frame, lru);
        if (kpage == f->kpage){
            break;
        }
    }
    if (e == list_end(&ft)){
        e = NULL;
        exit(-1);
    }

    palloc_free_page(f->kpage);
    pagedir_clear_page(f->t->pagedir, f->upage);
    
    list_remove(&f->lru);
    free(f);
}

void evict_frame(){
    struct list_elem *e;
    struct s_page *sp;
    struct frame *f;

    e = lru_pointer;
    f = list_entry(e, struct frame, lru);
    if (pagedir_is_accessed(f->t->pagedir, f->upage)){
        pagedir_set_accessed(f->t->pagedir, f->upage, false);

        for (; e != lru_pointer; ){
            f = list_entry(e, struct frame, lru);
            if (pagedir_is_accessed(f->t->pagedir, f->upage)){
                pagedir_set_accessed(f->t->pagedir, f->upage, false);
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

    sp = get_s_page(&thread_current()->s_pt, f->upage);
    sp->swap_index = swap_out(f->kpage);
    sp->status = 1;

    free_frame(f->kpage);
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