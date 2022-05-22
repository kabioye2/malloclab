#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "malloc.h"

static void check_consistency ();

typedef struct header{
  union {
    unsigned free : 1;
    size_t size_dirty;
  };
  struct header *next,*prev;
} header_t;

/*typedef struct free_header{
  union{
  unsigned free : 1;
  size_t size_dirty;
  };
  struct free_header next,prev;
  }free_header_t;*/

static void stamp_memory (header_t* h);
static void check_memory_stamp (header_t* h);
void insert (header_t* h);
void remove (header_t* h);
void* malloc_aligned (size_t alignment, size_t size);


typedef header_t footer_t;
//static int BIN_COUNT=15;


/*typedef struct bin{
  size_t sizeClass;
  header_t* head;
  }bin_t;*/


typedef struct {
  header_t* heap_start;
  void*     brk;
  header_t* bins[NBINS];
} params_t;

static params_t params = { NULL, NULL, {NULL}/* 
//implementation with bin struct
        {
        {8, NULL},
        {16, NULL},
        {24, NULL},
        {32, NULL},
                {40, NULL},
        {48, NULL},
        {56, NULL},
        {64, NULL},
        {72, NULL},
        {80, NULL},
        {88, NULL},
        {96, NULL},
        {104, NULL},
        {112, NULL},
        {120, NULL},
        {128, NULL},*/




};

static void* header_to_payload (header_t* h) {
  void* p = h + 1;
  assert (ALIGN (p) == p);
  return p;
}

static header_t* payload_to_header (void* p) {
  return p - sizeof (header_t);
}

// b could be a header or a footer
static size_t payload_size (void* b) {
  return ((footer_t*) b)->size_dirty & ~1;
}

// b could be a header or a footer
static size_t block_size (void* b) {
  return sizeof (header_t) + payload_size (b) + sizeof (footer_t);
}

static header_t* header_to_right_header (header_t* h) {
  void* nh = (void*) h + block_size (h);
  if (nh >= params.brk)
    return NULL;
  return (header_t*) nh;
}

static footer_t* header_to_footer (header_t* h) {
  return (footer_t*) ((void*) h + block_size (h) - sizeof (footer_t));
}

static footer_t* header_to_left_footer (header_t* h) {
  footer_t* f = (footer_t*) h - 1;
  if ((void*) f < (void*) params.heap_start)
    return NULL;
  return f;
}

static header_t* header_to_left_header (header_t* h) {
  footer_t* f = header_to_left_footer (h);
  if (f == NULL)
    return NULL;
  return (header_t*) ((void*) h - block_size (f));
}

static void write_size (header_t* b, size_t size, int free, int is_blocksize) {
  //if size is false(0), then skip if statement 
  if (size) {
    if (is_blocksize)
      size = size - sizeof (header_t) - sizeof (footer_t);
    else
      size = size;
    b->size_dirty = size;
  }

  b->free = free;//if free is 0, then block converted to used(not free)
  footer_t* f = header_to_footer (b);

  // Size before free!
  if (size)
    f->size_dirty = size;
  f->free = free;
}

static void* find_fit (size_t plsize) {//instead of iterating through all blocks, we only need to iterate through free list
//original(implicit list)  
//for (header_t* h = params.heap_start; h != NULL; h = header_to_right_header (h))
  //  if (h->free && payload_size (h) >= plsize)
  //    return h;
  //return NULL;

//old version(segregated lists):first find size class then iterate through list
  /*for(int i=0;i<BIN_COUNT-1;i++){
    if(plsize <= params.bins[i].sizeClass){
    return params.bins[i].head;
    }
    }*/


  //starting at first bin, iterate through bin. If not found, go to next bin and iterate through that bin, and so on...
  for(int bin_number = SIZE_TO_BIN (plsize); bin_number < NBINS; bin_number++){
    for(header_t* h=params.bins[bin_number];h !=NULL;h=h->next){
      if(payload_size(h) >= plsize){//if we find block we are looking for return that bin
        return h;
      }
    }
  }
  return NULL;
}

#define INIT_ALLOC 4096

static void init_malloc () {
  void* p = sbrk (0) + sizeof (header_t);
  size_t padding = ALIGN (p) - p;
  params.heap_start = padding + sbrk (padding + INIT_ALLOC);
  params.brk = sbrk (0);
  write_size (params.heap_start, INIT_ALLOC, 1, 1);//initializing the heap and on init has one free block. write_size=> writing to header of block(free or used)
  //head, prev, and next are initialized in insert function
  insert(params.heap_start);

  stamp_memory (params.heap_start);
}

#define MIN_PAYLOAD_SIZE (add_padding_to_payload_size (16))
#define MIN_BLOCK_SIZE (sizeof (header_t) + sizeof (footer_t) + MIN_PAYLOAD_SIZE)

// This rounds up a payload size so that plsize + footer + header is aligned.
static size_t add_padding_to_payload_size (size_t plsize) {
  size_t protuding = (plsize + sizeof (header_t) + sizeof (footer_t)) % ALIGNMENT;
  if (protuding != 0)
    return plsize + ALIGNMENT - protuding;
  return plsize;
}

static void* new_block_extend_heap (size_t plsize) {
  // Maybe check that left is free and coalesce?
  // header_t* left = header_to_left_header ((header_t*) params.brk);

  size_t minsize = sizeof (header_t) + plsize + sizeof (footer_t);
  assert (minsize >= MIN_BLOCK_SIZE);
  header_t* h = (header_t*) sbrk (minsize);
  write_size (h, plsize, 1, 0);
  params.brk = sbrk (0);
  insert(h);
  stamp_memory(h);//should not be necessary
  return h;
}

void* malloc (size_t plsize) {
  if (params.heap_start == NULL)
    init_malloc ();

  check_consistency ();

  plsize = add_padding_to_payload_size (plsize);
  if (plsize < MIN_PAYLOAD_SIZE)
    plsize = MIN_PAYLOAD_SIZE;

  header_t *b = find_fit (plsize);

  if (b == NULL) { // No match, enlarge heap.
    b = new_block_extend_heap (plsize);
        assert (b != NULL);
    check_consistency ();
  }
  //else
  remove(b);//if match remove from free list
  check_memory_stamp (b);
  assert (b->free);
  assert (payload_size (b) >= plsize);
  assert (block_size (b) <= ((uintptr_t) params.brk - (uintptr_t) b));


  // Split
  if (block_size (b) > sizeof (header_t) + plsize + sizeof (footer_t) + MIN_BLOCK_SIZE) {//is the block size big enough to where we can do a split
    size_t blsize = block_size (b);
    write_size (b, plsize, 1, 0);//changes the size of the block to the requested size
    header_t* n = header_to_right_header (b);//n is newly free block
    write_size (n, (uintptr_t) b + blsize - (uintptr_t) n, 1, 1);//creating a new header
    //new header for leftover free block
    //add new block to list
    assert(n->free);

    insert(n);//insert free block after split

    //if there is extra space in free block that is being converted to used. Then we split
    //When we split, the new free block has to be added to linked list
  }
  write_size (b, 0, 0, 0);//changes from free to used
  check_consistency ();
  return header_to_payload (b);
}

//for insert and remove, check 3 cases:
//-head
//-tail
//-middle

void insert (header_t* h){
  //new node is head, next is prev head
  //prev points to NULL
  //head is initially null

  int bin_index = SIZE_TO_BIN(payload_size(h));
  /*old version(segregated lists):
   * for(int i=0;i < BIN_COUNT-1;i++){
    if(payload_size(h)<=params.bins[i].sizeClass){
    bin_index = i;
    break;
    }
    }
  */


  h->next=params.bins[bin_index];
  h->prev=NULL;

  //base case: tail
  if(params.bins[bin_index] != NULL){
    params.bins[bin_index]->prev=h;
  }

  params.bins[bin_index]=h;

  check_consistency();
}

void remove (header_t* h){
  //prev points to null
  //next points to null
  //prev node points to next node and vice versa
  //need to account for one free block in list

int bin_index = SIZE_TO_BIN(payload_size(h));
  /*old version segregated lists:
   * for(int i=0;i < BIN_COUNT-1;i++){
    if(payload_size(h)<=params.bins[i].sizeClass){
    bin_index = i;
    break;
    }
    }
  */

  //if head removed, head=h->next and h->next->prev=null(h->prev)
  //if mid removed, h->next->prev=h->next and h->prev->next=h->prev
  //if tail removed, h->prev->next=null(h->next)
  if(params.bins[bin_index]==h){//remove head
    params.bins[bin_index]=h->next;
  }

  if(h->next != NULL){//remove head or mid
    h->next->prev=h->prev;
  }

  if(h->prev != NULL){//remove mid or last
    h->prev->next=h->next;
  }
  check_consistency();
}


void free (void* p) {
  if (p == NULL)
    return;

  header_t* h = payload_to_header (p);
  header_t* left = header_to_left_header (h);
  header_t* right = header_to_right_header (h);

  // Coalesce
  //remove block from free list if free blocks are next to each other then, coalesce and  put back in list

  if (left && left->free && right && right->free) {
    remove(left);
    remove(right);

    write_size (left, block_size (left) + block_size (h) + block_size (right), 1, 1);
    insert(left);
    stamp_memory (left);
  }
  else if (left && left->free) {
    remove(left);
    write_size (left, block_size (left) + block_size (h), 1, 1);
    insert(left);
    stamp_memory (left);
  }
  else if (right && right->free) {
    remove(right);
    write_size (h, block_size (h) + block_size (right), 1, 1);
    insert(h);
    stamp_memory (h);
  }
  else {
    write_size (h, 0, 1, 0);
    insert(h);//no adjacent blocks, add to freed block to free list
    stamp_memory (h);
  }

  check_consistency ();
}

void* malloc_aligned (size_t alignment, size_t size){
  //Accesses to main memory will be aligned if the address is a multiple of the size of the object being tracked down as given by the formula:
  //A mod s = 0
  //Where A is the address and s is the size of the object being accessed

  //-request memory with malloc
  //-You have a guarantee that alignment is a power of 2 larger than 128

  //first need an address
  //use modulo to compute the offset to move the malloc’d address to get required
  //alignment.
  void* ptr = (void*)malloc(alignment+size);


  size_t size_over = (size_t)ptr%alignment;//if zero then move to next aligned is same as alignment, else move is alignment(which would not be a multiple) - size over alignment(now multiple of alignment)
  //type should be size_t since multiple of alignment

  size_t offset = alignment-size_over;

  //next aligned address
  void* newPtr = ptr+offset;//You can only add or subtract integers to pointers


  return newPtr;//function should return a memory address that is a multiple of alignment
}


static void check_consistency () {
#ifndef NDEBUG
  for (header_t* h = params.heap_start; h != NULL; h = header_to_right_header (h)) {
    header_t* left = header_to_left_header (h);
    header_t* right = header_to_right_header (h);
    if (left)
      assert (h == header_to_right_header (left));
    if (right)
      assert (h == header_to_left_header (right));
    assert (((uintptr_t) h + sizeof (header_t)) % ALIGNMENT == 0);
    assert ((void*) h + block_size (h) <= params.brk);
    assert (h->size_dirty == (header_to_footer (h))->size_dirty);
  }
#endif
}

// This should be enough space to not clutter the payload of a free block.
#define STAMP_START(h)  ((void*) h + 40)

static void stamp_memory (header_t* h) {
#ifndef NDEBUG
  for (unsigned* p = STAMP_START (h); p < (unsigned*) header_to_footer (h) - 1; ++p)
    *p = 0xDEADBEEF;
#endif
}

static void check_memory_stamp (header_t* h) {
#ifndef NDEBUG
  for (unsigned* p = STAMP_START (h); p < (unsigned*) header_to_footer (h) - 1; ++p)
    assert (*p == 0xDEADBEEF);
#endif
}

void* realloc (void* p, size_t plsize) {
  if (p == NULL)
    return malloc (plsize);

  header_t* h = payload_to_header (p);
  size_t old_plsize = payload_size (h);
  void *p2 = malloc (plsize);
  memcpy (p2, p, plsize > old_plsize ? old_plsize : plsize);
  free (p);
  return p2;
}
                                                                                                                                                                                          425,1         Bot
