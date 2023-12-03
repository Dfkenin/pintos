#include "vm/page.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include <stdio.h>


unsigned hash_func(const struct hash_elem *e, void *aux UNUSED);
bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

/*
void s_pt_init(struct hash *s_pt);
void allocate_s_page(struct hash *s_pt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
struct s_page *get_s_page(struct hash *s_pt, void *upage);
bool lazy_load(struct hash *s_pt, void *upage, bool growth);
void free_s_page(struct hash *s_pt, struct s_page *sp);
void s_page_delete(struct hash *s_pt, struct s_page *sp);
void destructor(struct hash_elem *e, void *aux);
void s_pt_delete(struct hash *s_pt);
*/

void s_pt_init(struct hash *s_pt){
    hash_init(s_pt, hash_func, less_func, NULL);
}

unsigned hash_func(const struct hash_elem *e, void *aux UNUSED){
    const struct s_page *sp = hash_entry(e, struct s_page, hash_elem);
    return hash_bytes(&sp->upage, sizeof(sp->upage));
}

bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    const struct s_page *spa = hash_entry(a, struct s_page, hash_elem);
    const struct s_page *spb = hash_entry(b, struct s_page, hash_elem);
    return spa->upage < spb->upage;
}

void allocate_s_page(struct hash *s_pt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, int status){
    struct s_page *p;
    
    p = (struct s_page*)malloc(sizeof *p);
    p->kpage = NULL;
    p->upage = upage;

    p->file = file;
    p->ofs = ofs;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->writable = writable;

    p->status = status;

    hash_insert(s_pt, &p->hash_elem);
}

struct s_page *get_s_page(struct hash *s_pt, void *upage){
    struct s_page target;
    target.upage = pg_round_down(upage);
    struct hash_elem *elem = hash_find(s_pt, &target.hash_elem);
    return elem ? hash_entry(elem, struct s_page, hash_elem) : NULL;
}

bool lazy_load(struct hash *s_pt, void *fault_addr, bool growth){
    struct s_page *sp;
    void *upage = pg_round_down(fault_addr);

    sp = get_s_page(s_pt, upage);
    if (sp == NULL){ //case 나누면 stack growth도..?
        //printf("%d\n", growth);
        if (growth){
            if (fault_addr < PHYS_BASE - 2048*PGSIZE) {
                return false;
            }
            allocate_s_page(s_pt, upage, NULL, 0, 0, PGSIZE, true, 0);
            sp = get_s_page(s_pt, upage);
        }
        else{
            return false;
        }
    }

    //printf("lazy_load pass 1\n");
    // from process.c load_segment func.
    uint8_t *kpage = allocate_frame (PAL_USER, upage);
    if (kpage == NULL)
    return false;

    //printf("lazy_load pass 2 with status %d\n", sp->status);

    if (sp->status == 0){
        if (sp->file){
            if (file_read_at (sp->file, kpage, sp->read_bytes, sp->ofs) != (int) sp->read_bytes)
            {
                free_frame (kpage);
                return false;
            }
        }
        memset (kpage + sp->read_bytes, 0, sp->zero_bytes);
    }
    else if (sp->status == 1){
        swap_in(sp->swap_index, kpage);
    }
    else{
        return false;
    }

    //printf("lazy_load pass 3\n");

    struct thread *t = thread_current ();
    if (!(pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, sp->writable))) 
    {
        //printf("here condition %d\n", (pagedir_get_page(t->pagedir, upage) == NULL));
        free_frame (kpage);
        return false;
    }

    //printf("lazy_load pass 4\n");

    sp->kpage = kpage;
    sp->status = 2;
    return true;
}

void free_s_page(struct hash *s_pt, struct s_page *sp){
    hash_delete(s_pt, &sp->hash_elem);
    free(sp);
}

void s_page_delete(struct hash *s_pt, struct s_page *sp){
    hash_delete(s_pt, &sp->hash_elem);
    free(sp);
}

void destructor(struct hash_elem *e, void *aux UNUSED){
    struct s_page *sp;
    sp = hash_entry(e, struct s_page, hash_elem);
    free(sp);
}
void s_pt_delete(struct hash *s_pt){
    hash_destroy(s_pt, destructor);
}