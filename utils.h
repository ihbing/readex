#ifndef __UTILS_H__
#define __UTILS_H__

#include <inttypes.h>

extern int adler32(FILE *fp, uint32_t *result);
extern void die(const char *fmt, ...);
extern void *get_data(void *dst, long offset, size_t size, size_t nmemb, FILE *file);

#endif /* __UTILS_H__ */