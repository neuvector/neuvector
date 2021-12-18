#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bitmap.h"

#define bitmap_shift          5
#define bitmap_mask          31
#define bitmap_wordlength    32
#define bitmap_one        (bitmap_type)1

void bitmap_set(bitmap *b, int n)
{
    int word = n >> bitmap_shift;
    int position = n & bitmap_mask;
    b->array[word] |= bitmap_one << position;
}

void bitmap_clear(bitmap *b, int n)
{
    int word = n >> bitmap_shift;
    int position = n & bitmap_mask;
    b->array[word] &= ~(bitmap_one << position);
}

int bitmap_is_set(bitmap *b, int n)
{
    int word = n >> bitmap_shift;
    int position = n & bitmap_mask;
    return (b->array[word] >> position) & 1;
}

static int get_one_pos_from_word(bitmap_type w, int start)
{
    w = w >> start;
    while (w > 0) {
        if (w & 1) {
            return start;
        } else {
            w >>= 1;
            start++;
        }
    }
    return -1;
}

int bitmap_get_next_zero(bitmap *b, int n)
{
    int word, position;
    int idx, i, ret;
    bitmap_type tmp;

    if (n < 0 || n >= b->bits) {
        n = 0;
    }

    word = n >> bitmap_shift;
    position = n & bitmap_mask;
    tmp = ~b->array[word];
    idx = get_one_pos_from_word(tmp, position);
    if (idx >= 0) {
        ret = idx + (word << bitmap_shift);
        if (ret < b->bits) {
            return ret;
        }
    }

    i = word + 1;
    while (i < b->words) {
        tmp = ~b->array[i];
        if (tmp != 0) {
            idx = get_one_pos_from_word(tmp, 0);
            ret = idx + (i << bitmap_shift);
            if (ret < b->bits) {
                return ret;
            }
        }
        i++;
    };

    i = 0;
    while (i <= word) {
        tmp = ~b->array[i];
        if (tmp != 0) {
            idx = get_one_pos_from_word(tmp, 0);
            ret = idx + (i << bitmap_shift);
            if (ret < b->bits) {
                return ret;
            }
        }
        i++;
    };
    return -1;
}

bitmap *bitmap_allocate(int bits)
{
    bitmap *b = calloc(1, sizeof(bitmap));
    if (!b) {
        return NULL;
    }
    b->bits = bits;
    b->words = (bits + bitmap_wordlength - 1)/bitmap_wordlength;
    b->array = calloc(b->words, sizeof(bitmap_type));
    if (!b->array) {
        free(b);
        return NULL;
    }
    return b;
}

void bitmap_deallocate(bitmap *b)
{
    free(b->array);
    free(b);
}

//#define DP_BITMAP_TEST
#ifdef DP_BITMAP_TEST
void bitmap_print(bitmap *b)
{
    int i;
    for (i = 0; i < b->words; i++)
    {
        printf("%08x  " , b->array[i]);
    }
    printf("\n");
}

int main(void)
{
  const int testlen = 100;	// number of bits in the bitmap
  int i, j;
  bitmap *bm = bitmap_allocate(testlen);

  bitmap_print(bm);
  for (i = 0; i < testlen; i += 4) { bitmap_set(bm, i); }
  bitmap_print(bm);

  int free_bit = 0;
  for (i = 0; i < 120; i++) {
      free_bit = bitmap_get_next_zero(bm, free_bit+1);
      if (free_bit >= 0) {
          bitmap_set(bm, free_bit);
      } else {
          for (j = 0; j < testlen; j += 4) {bitmap_clear(bm, j);}
      }
      printf("Get free bit i %d, as %u\n", i, free_bit);
  }

  bitmap_deallocate(bm);
  return 0;
}
#endif
