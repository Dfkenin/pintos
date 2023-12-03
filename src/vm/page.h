#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/thread.h"
#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "vm/frame.h"

struct s_page{
    void *kpage;
    void *upage;
    struct hash_elem hash_elem;

    struct file *file;
    off_t file_ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    // informations from process.c load_segment function


    int swap_index;
    int page_id;
    int fid;
}





#endif /* vm/page.h */