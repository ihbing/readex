#ifndef __DEXTYPES_H__
#define __DEXTYPES_H__

#include <inttypes.h>

typedef uint8_t		u1;
typedef uint16_t 	u2;
typedef	uint32_t	u4;
typedef uint64_t	u8;

extern int readUnsignedLeb128(FILE *file, u4 *offset);
extern int readSignedLeb128(const u1 **pStream);

#define	sleb128(s)		readSignedLeb128(s)
#define uleb128(s)		readUnsignedLeb128(s)
#define uleb128p1(s)	(readUnsignedLeb128(s) + 1)

#endif	/* __DEXTYPES_H__ */