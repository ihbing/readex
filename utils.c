#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include "utils.h"

#define MAXLINE 	1024

/*
 * fatal error that dump core and terminate.
 */
void die(const char *fmt, ...) 
{
	char buf[MAXLINE];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, MAXLINE, fmt, ap);
	va_end(ap);

	perror(buf);

	abort();
	exit(EXIT_FAILURE);
}

int adler32(FILE *adler, uint32_t *result)
{
	int c;
	uint32_t A;
	uint32_t B;

	if(adler == NULL){
		fprintf(stderr, "invalid function parameter.\n");
		return -1;
	}

	A = 1;
	B = 0;

	while((c = fgetc(adler)) != EOF){
		#ifdef __debug__
		printf("c: %u\t\t\tA: %u\t\t\tB:%u\n", c, A, B);
		#endif
		A = (A + c) % 65521;
		B = (A + B) % 65521;
	}

	if(!feof(adler)){
		perror("[!] adler32 check failure");
		return -1;
	}

	*result = (B << 16) | A;
	return 0;
}

void *get_data(void *dst, long offset, size_t size, size_t nmemb, FILE *file)
{
	void *mdst;
	if(size == 0 || nmemb == 0)
		return NULL;
	if(fseek(file, offset, SEEK_SET)){
		fprintf(stderr, "get_data - unable to seek %#lx\n", offset);
		return NULL;
	}

	mdst = dst;
	if(mdst == NULL){
		mdst = malloc(size * nmemb);
		if(mdst == NULL){
			fprintf(stderr, "get_data - out of memory allocating %#lx\n", (unsigned long)(size * nmemb));
			return NULL;
		}
	}

	if(fread(mdst, size, nmemb, file) != nmemb){
		fprintf(stderr, "get_data - unable to read %#lx\n", (unsigned long)(size*nmemb));
		if(mdst != dst)
			free(mdst);
		return NULL;
	}

	return mdst;
}

