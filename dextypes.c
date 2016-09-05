#include <stdio.h>
#include <stdlib.h>
#include "dextypes.h"
#include "utils.h"

/* 
 *The codes in this file are all taken from dalvik's libdex/Leb128.h
 */

int readUnsignedLeb128(FILE *file, u4 *offset)
{

	u1 uleb;
    int result;
    int cnt = 0;
	if(fseek(file, *offset, SEEK_SET)){
		fprintf(stderr, "readUnsignedLeb128 - fseek %u failure.\n", *offset);
		exit(EXIT_FAILURE);
	}	

	if(get_data(&uleb, *offset, 1, 1, file) == NULL){
		fprintf(stderr, "readUnsignedLeb128 - get_data uleb failure.\n");
		exit(EXIT_FAILURE);
	}

	++(*offset);
	result = uleb;

    if (result > 0x7f) {
		if(get_data(&uleb, *offset, 1, 1, file) == NULL){
			fprintf(stderr, "readUnsignedLeb128 - get_data uleb failure.\n");
			exit(EXIT_FAILURE);
		}
		++(*offset);
        result = (result & 0x7f) | ((uleb & 0x7f) << 7);
        if (uleb > 0x7f) {
			if(get_data(&uleb, *offset, 1, 1, file) == NULL){
				fprintf(stderr, "readUnsignedLeb128 - get_data uleb failure.\n");
				exit(EXIT_FAILURE);
			}
			++(*offset);
            result |= (uleb & 0x7f) << 14;
            if (uleb > 0x7f) {
				if(get_data(&uleb, *offset, 1, 1, file) == NULL){
					fprintf(stderr, "readUnsignedLeb128 - get_data uleb failure.\n");
					exit(EXIT_FAILURE);
				}
				++(*offset);
                result |= (uleb & 0x7f) << 21;
                if (uleb > 0x7f) {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
					if(get_data(&uleb, *offset, 1, 1, file) == NULL){
						fprintf(stderr, "readUnsignedLeb128 - get_data uleb failure.\n");
						exit(EXIT_FAILURE);
					}
					++(*offset);
                    result |= uleb << 28;
                }
            }
        }
    }

    return result;
}

int readSignedLeb128(const u1 **pStream)
{
	const u1 *ptr = *pStream;
	int result = *(ptr++);
	if(result <= 0x7f){
		result = (result << 25) >> 25;
	}else{
		int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if(cur <= 0x7f){
			result = (result << 18) >> 18;
		}else{
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if(cur <= 0x7f){
				result = (result << 11) >> 11;
			}else{
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if(cur <= 0x7f){
					result = (result << 4) >> 4;
				}else{
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	*pStream = ptr;
	return result;
}