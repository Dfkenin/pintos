#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"
#include <stdio.h>
#include "vm/frame.h"
#include <stdbool.h>

struct s_page{
    void *kpage;
    void *upage;
    struct hash_elem hash_elem;

    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    // informations from process.c load_segment function


    size_t swap_index;
    int status;
    int page_id;
    int fid;
};


void s_pt_init(struct hash *s_pt);
unsigned hash_func(const struct hash_elem *e, void *aux);
bool less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void allocate_s_page(struct hash *s_pt, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable, int status);
struct s_page *get_s_page(struct hash *s_pt, void *upage);
bool lazy_load(struct hash *s_pt, void *fault_addr, bool growth);
void free_s_page(struct hash *s_pt, struct s_page *sp);
void destructor(struct hash_elem *e, void *aux);
void s_pt_delete(struct hash *s_pt);


#endif /* vm/page.h */