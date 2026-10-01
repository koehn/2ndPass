#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define HAVE_STDLIB_H 1
#define HAVE_BLF_H 1
static inline void mop_wipe(void *p, size_t n) { memset_s(p, n, 0, n); }
#define explicit_bzero mop_wipe
static inline void freezero(void *p, size_t n) { if (p) { mop_wipe(p, n); free(p); } }
