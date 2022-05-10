/* Benjamin Burke
 * Lab 1 - Malloc
 */

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"
#include "printing.h"

/* Due to the way assert() prints error messges we use out own assert function
 * for deteminism when testing assertions
 */
#ifdef TEST_ASSERT
  inline static void assert(int e) {
    if (!e) {
      const char * msg = "Assertion Failed!\n";
      write(2, msg, strlen(msg));
      exit(1);
    }
  }
#else
  #include <assert.h>
#endif

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t object_left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

void split(header * current, header * to_allocate, size_t rounded_size, size_t offset);

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_object_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->object_left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param object_left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t object_left_size) {
	set_object_state(fp,FENCEPOST);
	set_object_size(fp, ALLOC_HEADER_SIZE);
	fp->object_left_size = object_left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_object_state(hdr, UNALLOCATED);
  set_object_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->object_left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation

  if (raw_size == 0) {
    return NULL;
  }

  //check if raw_size needs to be rounded up to the nearest multiple of 8
  size_t r = raw_size % 8;
  size_t rounded_size = 0;

  //If it does, round up and add header size. If not, add header size
  if (r != 0) {
    rounded_size = (8 - r) + raw_size + ALLOC_HEADER_SIZE;
  }
  else {
    rounded_size = raw_size + ALLOC_HEADER_SIZE;
  }

  //if rounded_size is less than the size of header, set equal to size of header
  if (rounded_size < sizeof(header)) {
    rounded_size = sizeof(header);
  }

  int temp = (rounded_size - ALLOC_HEADER_SIZE) / 8;
  temp -= 1;
  if (temp < 0 || temp >= N_LISTS) {
    temp = N_LISTS - 1;
  }

  header * current;

  //loop through freelists
  for (int i = temp; i < N_LISTS; i++) {
    current = &freelistSentinels[i];
    if (current->next == &freelistSentinels[i]) {
      continue;
    }
    current = current->next;

    //loop through blocks in freelist
    while (1) {
      if (current == &freelistSentinels[i]) {
        break;
      }
      if (get_object_size(current) >= rounded_size) {
        size_t remainder = get_object_size(current) - rounded_size;

        //check if block is big enough to be split
        if (remainder > sizeof(header)) {
          //split block
          size_t offset = get_object_size(current) - rounded_size;
          header * to_allocate = get_header_from_offset(current, offset);
          split(current, to_allocate, rounded_size, offset);
          return (header *) to_allocate->data;
        }
        else {
          //allocate block
          current->prev->next = current->next;
          current->next->prev = current->prev;
          current->next = NULL;
          current->prev = NULL;
          set_object_state(current, ALLOCATED);
          return (header *) current->data;
        }
      }
      current = current->next;
    }
  }
  //allocate new chunk
  header * new_chunk = allocate_chunk(ARENA_SIZE);
  if (new_chunk == NULL) {
    return NULL;
  }

  //header for left fencepost
  header * left_fence = get_left_header(new_chunk);

  //check if new chunk is adjacent to the last chunk allocated
  if (get_right_header(lastFencePost) == left_fence) {

    //header for the previous block
    header * prev_block = get_left_header(lastFencePost);

    //check if we can coalesce
    if (get_object_state(prev_block) == UNALLOCATED) {
      int temp = (get_object_size(prev_block) - ALLOC_HEADER_SIZE) / 8;
      temp -= 1;
      if (temp < 0 || temp >= N_LISTS) {
        temp = N_LISTS - 1;
      }

      //update fenceposts to unallocated
      set_object_state(left_fence, UNALLOCATED);
      set_object_state(lastFencePost, UNALLOCATED);

      //update object_size and object_left_size
      size_t new_size = get_object_size(prev_block) + get_object_size(lastFencePost) + get_object_size(new_chunk) + get_object_size(left_fence);
      set_object_size(prev_block, new_size);

      lastFencePost = get_right_header(new_chunk);
      lastFencePost->object_left_size = get_object_size(prev_block);

      //update next and prev pointers
      int new_temp = (get_object_size(prev_block) - ALLOC_HEADER_SIZE) / 8;
      new_temp -= 1;
      if (new_temp < 0 || new_temp >= N_LISTS) {
        new_temp = N_LISTS - 1;
      }

      if (temp != new_temp) {
        header * t = &freelistSentinels[new_temp];
        if (prev_block->next != NULL) {
          prev_block->next->prev = prev_block->prev;
        }
        if (prev_block->prev != NULL) {
          prev_block->prev->next = prev_block->next;
        }
        if (t == t->next) {
          t->next = prev_block;
          t->prev = prev_block;
          prev_block->next = t;
          prev_block->prev = t;
        }
        else {
          prev_block->prev = t;
          prev_block->next = t->next;
          t->next->prev = prev_block;
          t->next = prev_block;
        }
      }
    }
    //previous block is allocated
    else if (get_object_state(prev_block) == ALLOCATED) {
      int temp = (get_object_size(prev_block) - ALLOC_HEADER_SIZE) / 8;
      temp -= 1;
      if (temp < 0 || temp >= N_LISTS) {
        temp = N_LISTS - 1;
      }

      //update fenceposts to unallocated
      set_object_state(left_fence, UNALLOCATED);
      set_object_state(lastFencePost, UNALLOCATED);

      //update object_size and object_left_size
      size_t new_size = get_object_size(lastFencePost) + get_object_size(new_chunk) + get_object_size(left_fence);
      set_object_size(lastFencePost, new_size);

      header * hdr = lastFencePost;

      lastFencePost = get_right_header(new_chunk);
      lastFencePost->object_left_size = get_object_size(hdr);

      //update next and prev pointers
      int new_temp = (get_object_size(hdr) - ALLOC_HEADER_SIZE) / 8;
      new_temp -= 1;
      if (new_temp < 0 || new_temp >= N_LISTS) {
        new_temp = N_LISTS - 1;
      }

      if (temp != new_temp) {
        header * t = &freelistSentinels[new_temp];
        if (t == t->next) {
          t->next = hdr;
          t->prev = hdr;
          hdr->next = t;
          hdr->prev = t;
        }
        else {
          hdr->prev = t;
          hdr->next = t->next;
          t->next->prev = hdr;
          t->next = hdr;
        }
      }
    }
  }
  //new chunk is not adjacent to the last chunk allocated
  else {
    insert_os_chunk(left_fence);
    int temp = (get_object_size(new_chunk) - ALLOC_HEADER_SIZE) / 8;
    temp -= 1;
    if (temp < 0 || temp >= N_LISTS) {
      temp = N_LISTS - 1;
    }

    //update lastFencePost to the new last fence post
    lastFencePost = get_right_header(new_chunk);

    //update next and prev pointers
    header * t = &freelistSentinels[temp];

    if (t == t->next) {
      t->next = new_chunk;
      t->prev = new_chunk;
      new_chunk->next = t;
      new_chunk->prev = t;
    }
    else {
      new_chunk->prev = t;
      new_chunk->next = t->next;
      t->next->prev = new_chunk;
      t->next = new_chunk;
    }
  }

  //new memory has been allocated, recursively call allocate_object
  return allocate_object(raw_size);
}

//Helper function for split condition
void split(header * current, header * to_allocate, size_t rounded_size, size_t offset) {
  int temp = (get_object_size(current) - ALLOC_HEADER_SIZE) / 8;
  temp -= 1;
  if (temp < 0 || temp >= N_LISTS) {
    temp = N_LISTS - 1;
  }

  set_block_object_size_and_state(to_allocate, rounded_size, ALLOCATED);
  set_object_size(current, offset);
  get_right_header(to_allocate)->object_left_size = rounded_size;
  to_allocate->object_left_size = offset;

  int new_temp = (get_object_size(current) - ALLOC_HEADER_SIZE) / 8;
  new_temp -= 1;
  if (new_temp < 0 || new_temp >= N_LISTS) {
    new_temp = N_LISTS - 1;
  }

  header * t = &freelistSentinels[new_temp];
  if (temp != new_temp) {
    current->prev->next = current->next;
    current->next->prev = current->prev;
    current->next = NULL;
    current->prev = NULL;
    if (t == t->next) {
      t->next = current;
      t->prev = current;
      current->next = t;
      current->prev = t;
    }
    else {
      current->prev = t;
      current->next = t->next;
      t->next->prev = current;
      t->next = current;
    }
  }
}
/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */
static inline void deallocate_object(void * p) {
  // TODO implement deallocation
  if (p == NULL) {
    return;
  }
  header * head = ptr_to_header(p);

  //double free check
  if (get_object_state(head) == UNALLOCATED) {
    printf("Double Free Detected\n");
    assert(0);
    return;
  }
  header * left = get_left_header(head);
  header * right = get_right_header(head);

  int temp = (get_object_size(head) - ALLOC_HEADER_SIZE) / 8;
  temp -= 1;
  if (temp < 0 || temp >= N_LISTS) {
    temp = N_LISTS - 1;
  }

  //coalesce with right block
  if (get_object_state(right) == UNALLOCATED && get_object_state(left) != UNALLOCATED) {
    size_t temp_size = get_object_size(right) + get_object_size(head);
    set_object_size(head, temp_size);
    set_object_state(head, UNALLOCATED);
    set_object_state(right, UNALLOCATED);
    get_right_header(head)->object_left_size = get_object_size(head);
    right->prev->next = right->next;
    right->next->prev = right->prev;
    right->next = NULL;
    right->prev = NULL;

    int new_temp = (get_object_size(head) - ALLOC_HEADER_SIZE) / 8;
    new_temp -= 1;
    if (new_temp < 0 || new_temp >= N_LISTS) {
      new_temp = N_LISTS - 1;
    }

    if (temp != new_temp) {
      header * t = &freelistSentinels[new_temp];
      if (t == t->next) {
        t->next = head;
        t->prev = head;
        head->next = t;
        head->prev = t;
      }
      else {
        head->prev = t;
        head->next = t->next;
        t->next->prev = head;
        t->next = head;
      }
    }
  }
  //coalesce with left block
  else if (get_object_state(left) == UNALLOCATED && get_object_state(right) != UNALLOCATED) {
    size_t temp_size = get_object_size(left) + get_object_size(head);
    set_object_size(left, temp_size);
    set_object_state(head, UNALLOCATED);
    set_object_state(left, UNALLOCATED);
    get_right_header(left)->object_left_size = get_object_size(left);
    left->prev->next = left->next;
    left->next->prev = left->prev;
    left->next = NULL;
    left->prev = NULL;

    int new_temp = (get_object_size(left) - ALLOC_HEADER_SIZE) / 8;
    new_temp -= 1;
    if (new_temp < 0 || new_temp >= N_LISTS) {
      new_temp = N_LISTS - 1;
    }

    if (temp != new_temp) {
      header * t = &freelistSentinels[new_temp];
      if (t == t->next) {
        t->next = left;
        t->prev = left;
        left->next = t;
        left->prev = t;
      }
      else {
        left->prev = t;
        left->next = t->next;
        t->next->prev = left;
        t->next = left;
      }
    }
  }
  //coalesce with both left and right blocks
  else if (get_object_state(right) == UNALLOCATED && get_object_state(left) == UNALLOCATED) {
    size_t temp_size = get_object_size(right) + get_object_size(head);
    set_object_size(head, temp_size);
    set_object_state(head, UNALLOCATED);
    set_object_state(right, UNALLOCATED);
    get_right_header(head)->object_left_size = get_object_size(head);
    right->prev->next = right->next;
    right->next->prev = right->prev;
    right->next = NULL;
    right->prev = NULL;

    temp_size = get_object_size(left) + get_object_size(head);
    set_object_size(left, temp_size);
    set_object_state(head, UNALLOCATED);
    set_object_state(left, UNALLOCATED);
    get_right_header(left)->object_left_size = get_object_size(left);
    left->prev->next = left->next;
    left->next->prev = left->prev;
    left->next = NULL;
    left->prev = NULL;

    int new_temp = (get_object_size(left) - ALLOC_HEADER_SIZE) / 8;
    new_temp -= 1;
    if (new_temp < 0 || new_temp >= N_LISTS) {
      new_temp = N_LISTS - 1;
    }

    if (temp != new_temp) {
      header * t = &freelistSentinels[new_temp];
      if (t == t->next) {
        t->next = left;
        t->prev = left;
        left->next = t;
        left->prev = t;
      }
      else {
        left->prev = t;
        left->next = t->next;
        t->next->prev = left;
        t->next = left;
      }
    }
  }
  //insert without coalescing
  else {
    header * t = &freelistSentinels[temp];
    set_object_state(head, UNALLOCATED);
    if (t == t->next) {
      t->next = head;
      t->prev = head;
      head->next = t;
      head->prev = t;
    }
    else {
      head->prev = t;
      head->next = t->next;
      t->next->prev = head;
      t->next = head;
    }
  }
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_object_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_object_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_object_size(chunk)  != get_right_header(chunk)->object_left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_object_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}
