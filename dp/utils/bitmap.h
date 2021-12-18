#ifndef __DP_BITMAP_H__
#define __DP_BITMAP_H__

#define bitmap_type        uint32_t

typedef struct {
    int bits;	// number of bits in the array
    int words;	// number of words in the array
    bitmap_type *array;
} bitmap;

void bitmap_set(bitmap *b, int n);

void bitmap_clear(bitmap *b, int n);
int bitmap_is_set(bitmap *b, int n);
int bitmap_get_next_zero(bitmap *b, int n);
bitmap *bitmap_allocate(int bits);
void bitmap_deallocate(bitmap *b);

#endif
