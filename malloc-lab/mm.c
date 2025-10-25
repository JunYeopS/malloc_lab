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


/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    int newsize = ALIGN(size + SIZE_T_SIZE);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1)
        return NULL;
    else
    {
        *(size_t *)p = size;
        return (void *)((char *)p + SIZE_T_SIZE);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;

    newptr = mm_malloc(size);
    if (newptr == NULL)
        return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
        copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}