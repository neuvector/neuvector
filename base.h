#ifndef __BASE_H__
#define __BASE_H__

#include <inttypes.h>

typedef unsigned char bool;

#undef true
#undef false
#define true  1
#define false 0

#define max(x,y) (((x)>(y))?(x):(y))
#define min(x,y) (((x)<(y))?(x):(y))

#ifndef likely
# define likely(x)        __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)        __builtin_expect(!!(x), 0)
#endif

#define DP_MNT_SHM_NAME "/dp_mnt.shm"

#define MAX_DP_THREADS 4

typedef struct dp_mnt_shm_ {
    uint32_t dp_hb[MAX_DP_THREADS];
	bool dp_active[MAX_DP_THREADS];
} dp_mnt_shm_t;

#endif
