#include "vm/page.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"


void s_pt_init(struct hash *s_pt);
unsigned hash_func(const struct hash_elem *e, void *aux UNUSED);
bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
void allocate_s_page(struct hash *s_pt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
struct s_page *get_s_page(struct hash *s_pt, void *upage);
bool lazy_load(struct hash *s_pt, void *upage, bool growth);
void free_s_page(struct hash *s_pt, struct s_page *sp);
void s_page_delete(struct hash *s_pt, struct s_page *sp);
void destructor(struct hash_elem *e, void *aux);
void s_pt_delete(struct hash *s_pt);

void s_pt_init(struct hash *s_pt){
    hash_init(s_pt, hash_func, less_func, NULL);
}

unsigned hash_func(const struct hash_elem *e, void *aux UNUSED){
    const struct s_page *sp = hash_entry(e, struct s_page, hash_elem);
    return hash_bytes(&sp->upage, sizeof(p->upage));
}

bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    const struct s_page *spa = hash_entry(a, struct s_page, hash_elem);
    const struct s_page *spb = hash_entry(b, struct s_page, hash_elem);
    return spa->upage < spb->upage;
}

void allocate_s_page(struct hash *s_pt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
    struct s_page *p;
    
    p = (struct s_page*)malloc(sizeof(struct s_page));
    p->kpage = NULL;
    p->upage = upage;

    p->file = file;
    p->ofs = ofs;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->writable = writable;

    p->swap_index = -1;

    hash_insert(s_pt, &p->hash_elem);
}

struct s_page *get_s_page(struct hash *s_pt, void *upage){
    struct s_page target;
    target.upage = pg_round_down(upage);
    struct hash_elem *elem = hash_find(s_pt, &target.hash_elem);
    return elem ? hash_entry(elem, struct s_page, hash_elem) : NULL;
}

bool lazy_load(struct hash *s_pt, void *upage, bool growth){
    struct s_page *sp;

    sp = get_s_page(s_pt, upage);
    if (sp == NULL){ //case 나누면 stack growth도..?   
        if (growth){
            if (upage < PHYS_BASE - 2048*PGSIZE) {
                return false;
            }
            if (!get_s_page(s_pt, upage)){
                allocate_s_page(s_pt, upage, NULL, 0, 0, 0, true);
                sp = get_s_page(s_pt, upage);
            }
        } 
        return false;
    }

    // from process.c load_segment func.
    uint8_t *kpage = allocate_frame (PAL_USER, upage);
    if (kpage == NULL)
    return false;

    if (sp->swap_index == -1){
        if (sp->file){
            if (file_read (sp->file, kpage, sp->read_bytes) != (int) sp->read_bytes)
            {
                free_frame (kpage);
                return false;
            }
        }
        memset (kpage + sp->read_bytes, 0, sp->zero_bytes);
    }
    else{
        swap_in(e->swap_id, kpage);
    }

    

    struct thread *t = thread_current ();
    if (!(pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, sp->writable))) 
    {
        free_frame (kpage);
        return false;
    }


    sp->kpage = kpage;
    return true;
}

void free_s_page(struct hash *s_pt, struct s_page *sp){
    hash_delete(s_pt, &sp->hash_elem);
    free(sp);
}

void s_page_delete(struct hash *s_pt, struct s_page *sp){
    hash_delete(s_pt, sp->hash_elem);
    free(sp);
}

void destructor(struct hash_elem *e, void *aux){
    struct s_page *sp;
    sp = hash_entry(e, struct s_page, hash_elem);
    free(sp);
}
void s_pt_delete(struct hash *s_pt){
    hash_destroy(s_pt, destructor);
}