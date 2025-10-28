/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

static void insert_free_block(void *bp);
static void remove_free_block(void *bp);

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "Team 8: ",
    /* First member's full name */
    "JunyeopS",
    /* First member's email address */
    "wnsduq6291@gmail.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8 // 정렬 단위 

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7) //정렬을 위한 패딩 작업 
// #define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x3) // 4바이트 정렬 할때 

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/* 단위(word) 크기 정의 */
#define WSIZE       4           // word = 4바이트 (헤더/풋터 크기)
#define DSIZE       8           // double word = 8바이트 (정렬 단위)

/* 힙을 한 번 확장할 때 기본 크기 (초기 힙 크기 단위) */
#define CHUNKSIZE   (1 << 12)   // 4096바이트 (4KB 단위로 힙 확장)

/* 크기와 할당 비트를 하나의 값으로 묶어서 저장 */
#define PACK(size, alloc)  ((size) | (alloc))  
// ex) 헤더에 크기(size)와 할당 여부(alloc: 0 또는 1)를 합쳐서 기록

/* 주소 p가 가리키는 워드(4바이트) 읽기/쓰기 */
#define GET(p)       (*(unsigned int *)(p))       // 해당 주소의 값 읽기
#define PUT(p, val)  (*(unsigned int *)(p) = (val)) // 해당 주소에 값 저장

/* 헤더 또는 풋터에서 블록의 크기와 할당 비트 추출 */
#define GET_SIZE(p)  (GET(p) & ~0x7)   // 하위 3비트 제외(000...111 제거) → 블록 크기
#define GET_ALLOC(p) (GET(p) & 0x1)    // 가장 마지막 비트(LSB)만 추출 → 0: free, 1: allocated

/* 주어진 블록 포인터(bp)로 헤더와 풋터 주소 계산 */
#define HDRP(bp)       ((char *)(bp) - WSIZE)                 // 현재 블록의 헤더 주소
#define FTRP(bp)       ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) // 현재 블록의 풋터 주소

/* 이전, 다음 블록의 포인터 계산 */
#define NEXT_BLKP(bp)  ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))  
// 현재 블록 크기만큼 더해서 다음 블록으로 이동
#define PREV_BLKP(bp)  ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))  
// 이전 블록의 풋터에서 크기를 읽어서 이전 블록으로 이동

static char *heap_listp = NULL; // 힙의 시작 포인터

// free-list 매크로
static char *free_listp = NULL; // for explicit

#define PRED_PTR(bp)      ((void **)(bp))           // prev 저장 위치
#define NEXT_PTR(bp)      ((void **)(bp) + 1)       // next 저장 위치

#define GET_PRED(bp)      (*(void **)(bp))
#define GET_NEXT(bp)      (*((void **)(bp) + 1))
#define SET_PRED(bp, p)   (*(void **)(bp) = (p))
#define SET_NEXT(bp, p)   (*((void **)(bp) + 1) = (p))

#define MINBLK   24

static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))); // 이전 블록의 할당 상태
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp))); // 다음 블록의 할당 상태
    size_t size = GET_SIZE(HDRP(bp));                   // 현재 블록 크기

    // Case 1: 이전, 다음 모두 할당 (병합 안 함)
    if (prev_alloc && next_alloc)
    {
        return bp;
    }

    // Case 2: 다음 블록만 가용 (뒤 블록과 병합)
    else if (prev_alloc && !next_alloc)
    {
        remove_free_block(NEXT_BLKP(bp));  
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));    // 다음 블록 크기 추가
        PUT(HDRP(bp), PACK(size, 0));             
        PUT(FTRP(bp), PACK(size, 0));            
    }

    // Case 3: 이전 블록만 가용 (앞 블록과 병합)
    else if (!prev_alloc && next_alloc)
    {
        void *prev_bp = PREV_BLKP(bp);
        remove_free_block(PREV_BLKP(bp));
        size += GET_SIZE(HDRP(prev_bp));
        bp = prev_bp;
        PUT(HDRP(bp), PACK(size, 0));  // 헤더 갱신
        PUT(FTRP(bp), PACK(size, 0));             
    }

    // Case 4: 이전, 다음 모두 가용 (양쪽 병합)
    else
    {
        void *prev_bp = PREV_BLKP(bp);
        void *next_bp = NEXT_BLKP(bp);
        remove_free_block(prev_bp);
        remove_free_block(next_bp);
        size += GET_SIZE(HDRP(prev_bp)) + GET_SIZE(HDRP(next_bp));
        bp = prev_bp;
        PUT(HDRP(bp), PACK(size, 0));  // 헤더 갱신
        PUT(FTRP(bp), PACK(size, 0));  // 풋터 갱신
    }

    return bp; // 병합된 블록의 시작 주소 반환
}

static void *extend_heap(size_t words)
{
    char *bp;
    size_t size;

    // 요청한 워드를 짝수 단위로 올림 (정렬 유지)
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;

    if ((bp = mem_sbrk(size)) == (void *)-1)
        return NULL;

    // 새 free block의 header와 footer 설정
    PUT(HDRP(bp), PACK(size, 0));         // Free block header
    PUT(FTRP(bp), PACK(size, 0));         // Free block footer
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); // 새 Epilogue header 

    //새로 받은 메모리
    bp = coalesce(bp);
    insert_free_block(bp);

    return bp; // 인접 free block과 병합 후 반환
}

/* mm_init - initialize the malloc package. */
int mm_init(void)
{
    // 1. 힙에 4워드(16바이트) 공간 요청: padding + prologue header/footer + epilogue header
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;
    // 2. 초기 힙 구성
    PUT(heap_listp, 0);                             // 정렬용 padding
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1));  // Pro header (8바이트, 할당 상태)
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1));  // Pro footer
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));      // Epil header (크기 0, 할당됨)
    heap_listp += (2 * WSIZE);                      // payload 시작 지점(bp) 설정
    free_listp = NULL;

    // 3. 초기 힙을 CHUNKSIZE 만큼 확장 (free block 하나 만들기)
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;
    return 0;
}

static void *find_fit(size_t asize)
{
    void *bp;
    void *best_p = NULL;
    for (bp = free_listp; bp != NULL; bp = GET_NEXT(bp)) {

        if (GET_ALLOC(HDRP(bp)) == 0 && asize <= GET_SIZE(HDRP(bp))) {
            // bestp가 NULL일때 첫 번째 후보를 설정하는 단계
            if (best_p == NULL || GET_SIZE(HDRP(bp)) < GET_SIZE(HDRP(best_p))) {
                    best_p = bp;
                }
        }
    }
    return best_p;
}

static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));

    remove_free_block(bp);

    if ((csize - asize) >= (MINBLK)) { // 남는 공간이 충분하면 분할 16 free 4+4 + 16 =24
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));
        SET_PRED(bp, NULL);
        SET_NEXT(bp, NULL);
        //남은 블럭 다시 넣어주기 
        insert_free_block(bp);
    } else { // 아니면 통째로 사용
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

/* mm_malloc - Allocate a block by incrementing the brk pointer.
 * Always allocate a block whose size is a multiple of the alignment. */
void *mm_malloc(size_t size)
{
    if (size == 0) return NULL;
    
    size_t asize = ALIGN(size + 2*WSIZE); // payload + header + footer
    if (asize < MINBLK) asize = MINBLK;   // prev/next 포인터 들어갈 최소 크기 보장

    void *bp;
    // 가용 블록 탐색
    if ((bp = find_fit(asize)) != NULL) {
        place(bp, asize);
        return bp;
    }

    // 못 찾으면 힙 확장
    size_t extendsize = (asize < CHUNKSIZE) ? CHUNKSIZE : asize;
    if ((bp = extend_heap(extendsize / WSIZE)) == NULL)
        return NULL;

    place(bp, asize);
    return bp;
}

// manage free list (insert/remove) LIFO
static void insert_free_block(void *bp) {

    //free block paylaod에 next , prev 주소값 넣기
    SET_PRED(bp, NULL); 
    SET_NEXT(bp, free_listp);

    // 기존 head의 prev 갱신
    if (free_listp != NULL)
        SET_PRED(free_listp, bp);

    // head 갱신
    free_listp = bp;
}
static void remove_free_block(void *bp) {
    if (bp == NULL) return;

    char *prev = GET_PRED(bp);
    char *next = GET_NEXT(bp);

    if (prev) 
        SET_NEXT(prev, next);
    else     
        free_listp = next;

    if (next) SET_PRED(next, prev);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
    size_t size = GET_SIZE(HDRP(bp));  // 현재 블록의 크기 읽기

    PUT(HDRP(bp), PACK(size, 0));  // 헤더에 크기+할당비트(0:free)
    PUT(FTRP(bp), PACK(size, 0));  // 풋터 동일 
    
    // 병합 과정에서 틀어진거 bp재갱신 
    bp = coalesce(bp);                  
    insert_free_block(bp);

}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    // saver 
    if (ptr == NULL) return mm_malloc(size);
    if (size == 0)   { mm_free(ptr); return NULL; }

    void *newptr;
    size_t copySize;

    newptr = mm_malloc(size);
    if (newptr == NULL)
        return NULL;
    
    size_t old_block = GET_SIZE(HDRP(ptr));
    size_t old_payload = old_block - 2*WSIZE;    //header, footer 제외 

    copySize = (size < old_payload) ? size : old_payload;

    memcpy(newptr, ptr, copySize);
    mm_free(ptr);
    return newptr;
}