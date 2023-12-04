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
    lru_pointer = NULL;
}

void *allocate_frame(enum palloc_flags flags, void *upage){
    struct frame *f;
    void *kpage;
    
    //printf("allocate_frame 0\n");
    kpage = palloc_get_page(flags);
    //printf("allocate_frame 1\n");
    if (kpage == NULL){
        //printf("allocate_frame 2\n");
        evict_frame();
        //printf("allocate_frame 3\n");
        kpage = palloc_get_page(flags);
        if (kpage == NULL){
            //printf("allocate_frame 4\n");
            return NULL;
        }
    }
    //printf("allocate_frame 5\n");

    f = (struct frame*)malloc(sizeof(struct frame));
    //printf("allocate_frame 6\n");
    f->fid = allocate_fid();
    f->kpage = kpage;
    f->upage = upage;
    f->t = thread_current();
    list_push_back(&ft, &f->lru);
    
    //printf("allocate_frame 7\n");

    return f->kpage;
}

void *free_frame(void *kpage){
    struct frame *f;
    struct list_elem *e;
    printf("free 0\n");
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)){
        f = list_entry(e, struct frame, lru);
        if (kpage == f->kpage){
            break;
        }
    }
    printf("free 1\n");
    if (e == list_end(&ft)){
        exit(-1);
    }
    printf("free 2\n");

    palloc_free_page(f->kpage);
    printf("free 3\n");
    pagedir_clear_page(f->t->pagedir, f->upage);
    //printf("free 4\n");
    
    lru_pointer = list_remove(&f->lru);
    //printf("lru_pointer now at %p\n", lru_pointer);
    free(f);
    //printf("free 5\n");
}

void evict_frame(){
    struct list_elem *e = lru_pointer;
    struct s_page *sp;
    struct frame *f;
    //printf("evict_frame 0\n");
    
    if (e == NULL){
        //printf("evict_frame 1\n");
        e = list_begin(&ft);
        lru_pointer = e;
        //printf("e : %p, lru_pointer : %p\n", e, lru_pointer);
    }
    //printf("evict_frame 2\n");

    f = list_entry(e, struct frame, lru);
    while (!pagedir_is_accessed(f->t->pagedir, f->upage)){
        //printf("where 1\n");
        pagedir_set_accessed(f->t->pagedir, f->upage, false);

        if (list_next(e) == list_end(&ft)){
            e = list_begin(&ft);
            //printf("to beginning\n");
        }
        else{
            e = list_next(e);
            //printf("e : %p\n");
        }
        f = list_entry(e, struct frame, lru);
        //printf("where 3\n");
    }
    
    //printf("evict_frame 3\n");

    sp = get_s_page(&thread_current()->s_pt, f->upage);
    sp->swap_index = swap_out(f->kpage);
    sp->status = 1;
    //printf("evict_frame 4\n");

    free_frame(f->kpage);
    //printf("evict_frame 5\n");
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