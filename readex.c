#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "dex.h"
#include "utils.h"

//#define __debug__

#define PROGRAM_NAME	"readex"
#define PROGRAM_VER		"0.01"
#define DEX_MAGIC		"dex\n035"
#define DEX_MAGIC_FMT	"dex\\n035\\0"
#define BUFFLEN			1024
#define NO_INDEX		0xFFFFFFFF

#define OFFSETOF(type, member)		(size_t)&(((type *)0)->member)

static int do_dex_header = 0;
static int do_string_ids = 0;
static int do_method_ids = 0;
static int do_class_defs = 0;
static int do_help = 0;

static char *class_name = NULL;
static DexHeader *dex_header = NULL;
static StringIdItem *str_item = NULL;
static TypeIdIndex *type_ids = NULL;
static ProtoIds *proto_ids = NULL;
static FieldIds *field_ids = NULL;
static MethodIds *method_ids = NULL;
static ClassDefs *class_defs = NULL;
static char **str_ids = NULL;
static FILE *dex = NULL;

static int access_flags_mask = ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL 
								| ACC_SYNCHRONIZED | ACC_SUPER | ACC_VOLATILE | ACC_BRIDGE | ACC_TRANSIENT
								| ACC_VARARGS | ACC_NATIVE | ACC_INTERFACE | ACC_ABSTRACT | ACC_STRICT
								| ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM | ACC_CONSTRUCTOR | ACC_DECLARED_SYNCHRONIZED;

static AccessFlags afs[] = {
	{ACC_PUBLIC, CLASS|FIELD|METHOD, "public"},
	{ACC_PRIVATE, FIELD|METHOD, "private"},
	{ACC_PROTECTED, FIELD|METHOD, "protected"},
	{ACC_STATIC, FIELD|METHOD, "static"},
	{ACC_FINAL, CLASS|FIELD|METHOD, "final"},
	{ACC_SYNCHRONIZED, METHOD, "synchronized"},
	{ACC_SUPER, CLASS, "super"},
	{ACC_VOLATILE, FIELD, "volatile"},
	{ACC_BRIDGE, METHOD, "bridge"},
	{ACC_TRANSIENT, FIELD, "transient"},
	{ACC_VARARGS, METHOD, "varargs"},
	{ACC_NATIVE, METHOD, "native"},
	{ACC_INTERFACE, CLASS, "interface"},
	{ACC_ABSTRACT, CLASS|METHOD, "abstract"},
	{ACC_STRICT, METHOD, "strict"},
	{ACC_SYNTHETIC, FIELD|METHOD, "synthetic"},
	{ACC_ANNOTATION, CLASS, "annotation"},
	{ACC_ENUM, CLASS|FIELD, "enum"},
	{ACC_CONSTRUCTOR, METHOD, "constructor"},
	{ACC_DECLARED_SYNCHRONIZED, METHOD, "declared synchronized"},
	{0, 0, 0},
};

static void usage(void);
static void print_header_info(DexHeader *dex_header);
static int check_sha1(void);
static void process_dex_header(void);
static char *process_string_items(u4 offset);
static void free_str_ids(void);
static void process_string_ids(void);
static void process_type_ids(void);
static int process_type(char *buffer, size_t len, u4 idx);
static int process_method_paras(char *buffer, size_t len, int offset);
static char *process_method_item(MethodIds *method, int has_class_name);
static void process_proto_ids(void);
static char *process_field_item(u4 idx, int has_class_name);
static void process_field_ids(void);
static void process_method_ids(int has_class_name);
static char *_get_class_name(u4 idx);
static char *get_class_name(ClassDefs *class);
static char *_get_access_flags(int flags, int type);
static char *get_access_flags(ClassDefs *class, int type);
static char *get_super_name(ClassDefs *class);
static char *get_interfaces(ClassDefs *class);
static char *process_source_idx(ClassDefs *class);
static char *process_annotation(ClassDefs *class);
static char *process_class_data(ClassDefs *class);
static void process_class_items(ClassDefs *class);
static void process_class_type(void);
static void parse_args(int argc, char **argv);
static void process_file(const char *file);

static void usage(void)
{
	puts(" Usage: readex -[mCHhs] [-c class_name] dex_file_name");
	puts(" \t-m, --method                                show all methods' information in dex file.");
	puts(" \t-C, --Class                                 show all classes' information in dex file.");
	puts(" \t-c [class name], --class [class name]       show specific class's information in dex file.");
	puts(" \t-H, --header                                show header information in dex file.");
	puts(" \t-s, --strings                               show all strings in dex file.");
	puts(" \t-h, --help                                  show this message.");
}

static int check_sha1(void)
{
	return 0;
}

static void process_dex_header(void)
{	
	uint32_t adler;

	fseek(dex, OFFSETOF(DexHeader, signature), SEEK_SET);

	if(adler32(dex, &adler) != 0){
		fprintf(stderr, "process_dex_header - get adler32 checksum failure.\n");
		exit(EXIT_FAILURE);
	}

	if(check_sha1()){
		// check sha1 checksum
	}

	dex_header = (DexHeader *)get_data(NULL, 0, sizeof(DexHeader), 1, dex);

	if(dex_header == NULL){
		fprintf(stderr, "process_dex_header - get dex header failure.\n");
		exit(EXIT_FAILURE);
	}


	if(dex_header->checksum != adler){
		fprintf(stderr, "process_dex_header - adler32 checksum check failure.\n");
		exit(EXIT_FAILURE);
	}

	if(strncmp((const char *)(dex_header->magic), DEX_MAGIC, sizeof(DEX_MAGIC)) != 0){
		fprintf(stderr, "process_dex_header - wrong magic bytes not a dex file\n");
		exit(EXIT_FAILURE);
	}

	// print the header info
	if(do_dex_header)
		print_header_info(dex_header);
}

static void print_header_info(DexHeader *dex_header)
{	
	int i;
	if(dex_header == NULL)
		return ;
	puts("Dex Header:");
	printf(" Magic: ");
	for(i = 0; i < sizeof(dex_header->magic); ++i){
		printf("%2.2x ", dex_header->magic[i]);
	}
	printf("   (%s)\n", DEX_MAGIC_FMT);
	printf(" Checksum:                       %08X\n", dex_header->checksum);
	printf(" Signature:                      ");
	for(i = 0; i < kSHA1DigestLen; ++i)
		printf("%02X", dex_header->signature[i]);
	printf("\n");
	printf(" File Size:                 %8X(%d) bytes\n", dex_header->fileSize, dex_header->fileSize);
	printf(" Header Size:              %8X(%d) bytes\n", dex_header->headerSize, dex_header->headerSize);
	// endian prompt string
	printf(" Endian Tag:                     %s", dex_header->endianTag == 0x12345678 ? "little endian" : 
					 					    dex_header->endianTag == 0x87654321 ? "big endian" :
										    "unknown endian(invalid endian tag)");
	printf("(%8X)\n", dex_header->endianTag);
	printf(" LinkSize:                %8X(%d)\n", dex_header->linkSize, dex_header->linkSize);
	printf(" Link Offset:             %8X(%d)\n", dex_header->linkOff, dex_header->linkOff);
	printf(" Map Offset:                %8X(%d)\n", dex_header->mapOff, dex_header->mapOff);
	printf(" String ID Size:          %8X(%d)\n", dex_header->stringIdsSize, dex_header->stringIdsSize);
	printf(" String ID Offset:         %8X(%d)\n", dex_header->stringIdsOff, dex_header->stringIdsOff);
	printf(" Type ID Size:            %8X(%d)\n", dex_header->typeIdsSize, dex_header->typeIdsSize);
	printf(" Type ID Offset:           %8X(%d)\n", dex_header->typeIdsOff, dex_header->typeIdsOff);
	printf(" Method Proto Size:       %8X(%d)\n", dex_header->protoIdsSize, dex_header->protoIdsSize);
	printf(" Method Proto Offset:      %8X(%d)\n", dex_header->protoIdsOff, dex_header->protoIdsOff);
	printf(" Field ID Size:           %8X(%d)\n", dex_header->fieldIdsSize, dex_header->fieldIdsSize);
	printf(" Field ID Offset:          %8X(%d)\n", dex_header->fieldIdsOff, dex_header->fieldIdsOff);
	printf(" Method ID Size:          %8X(%d)\n", dex_header->methodIdsSize, dex_header->methodIdsSize);
	printf(" Method ID Offset:         %8X(%d)\n", dex_header->methodIdsOff, dex_header->methodIdsOff);
	printf(" Class Define Size:       %8X(%d)\n", dex_header->classDefsSize, dex_header->classDefsSize);
	printf(" Class Define Offset:       %8X(%d)\n", dex_header->classDefsOff, dex_header->classDefsOff);
	printf(" Data Size:                 %8X(%d)\n", dex_header->dataSize, dex_header->dataSize);
	printf(" Data Offset:               %8X(%d)\n", dex_header->dataOff, dex_header->dataOff);
}

static char *process_string_items(u4 offset)
{
	char *buffer, *buffer_back;
	int i, j;
	int str_len;
	int newline = 0;

	if(dex_header == NULL)
		process_dex_header();

	str_len = readUnsignedLeb128(dex, &offset);

	if(str_len < 0){
		fprintf(stderr, "process_string_items - invalid string length at %x.\n", offset);
		return NULL;
	}

	// apply 2 times of char space for transforming \n to \\n
	buffer = (char *)malloc(sizeof(char) * (str_len * 2));
	if(buffer == NULL){
		fprintf(stderr, "process_string_items - malloc failure out of memory.\n");
		return NULL;
	}

	if(get_data(buffer, offset, str_len, 1, dex) == NULL){
		fprintf(stderr, "process_string_items - get string failure.\n");
		return NULL;
	}

	buffer[str_len] = '\0';

	for(i = 0; i < str_len; ++i){
		if(buffer[i] == '\n'){
			newline = 1;
		}
	}

	if(newline){
		buffer_back = (char *)malloc(sizeof(char) * str_len * 2);
		if(buffer_back == NULL){
			fprintf(stderr, "process_string_items - malloc failure out of memory.\n");
			free(buffer);
			return NULL;
		}
		for(j = 0, i = 0; i < str_len; ++i, ++j){
			// just handle the newline character.
			// skip other invisible character
			if(buffer[i] == '\n'){
				buffer_back[j++] = '\\';
				buffer_back[j] = 'n';
			}else{
				buffer_back[j] = buffer[i];
			}
		}
		memcpy(buffer, buffer_back, j);
		buffer[j] = '\0';
		free(buffer_back);
	}

	return buffer;
}

static void free_str_ids(void)
{
	int i;
	if(str_ids != NULL){
		if(dex_header == NULL)
			process_dex_header();

		for(i = 0; i < dex_header->stringIdsSize; ++i){
			free(str_ids[i]);
		}
		free(str_ids);
	}
}

static void process_string_ids(void)
{
	int i;
	if(dex_header == NULL){
		process_dex_header();
	}

	if(str_ids != NULL){
		free_str_ids();
	}

	str_ids = (char **)malloc(sizeof(char *) * dex_header->stringIdsSize);
	if(str_ids == NULL){
		fprintf(stderr, "process_string_ids - malloc failure out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if(str_item == NULL){
		str_item = (StringIdItem *)get_data(NULL, dex_header->stringIdsOff, sizeof(StringIdItem), dex_header->stringIdsSize, dex);
		if(str_item == NULL){
			fprintf(stderr, "process_string_ids - get string ids data failure.\n");
			exit(EXIT_FAILURE);
		}
	}

	for(i = 0; i < dex_header->stringIdsSize; ++i)
		str_ids[i] = process_string_items(str_item[i].string_data_off);

	if(do_string_ids){
		puts("Strings:");
		for(i = 0; i < dex_header->stringIdsSize; ++i){
			printf(" %2d(%8X):       \"%s\"\n", i, str_item[i].string_data_off, str_ids[i] == NULL ? "null" : str_ids[i]);
		}
	}
}

static void process_type_ids(void)
{
	if(dex_header == NULL){
		process_dex_header();
	}

	if(type_ids == NULL){
		type_ids = (TypeIdIndex *)get_data(NULL, dex_header->typeIdsOff, sizeof(TypeIdIndex), dex_header->typeIdsSize, dex);
		if(type_ids == NULL){
			fprintf(stderr, "process_type_ids - get type index items failure.\n");
			return ;
		}
	}
#if 0
	if(do_type_ids){
		if(str_ids == NULL){
			process_string_ids(dex);
		}
		puts("Type Index:");
		for(i = 0; i < dex_header->typeIdsSize; ++i){
			printf(" %2d(idx: %4d)        %s\n", i, type_ids[i].descriptor_idx, str_ids[type_ids[i].descriptor_idx]);
		}
	}
#endif

}

static const char *trans_dex_type_name(char sht)
{
	switch(sht){
		case 'V':
			return "void";
			break;
		case 'Z':
			return "boolean";
			break;
		case 'B':
			return "byte";
			break;
		case 'S':
			return "short";
			break;
		case 'C':
			return "char";
			break;
		case 'I':
			return "int";
			break;
		case 'J':
			return "long";		// 64bits
			break;
		case 'F':
			return "float";
			break;
		case 'D':
			return "double";	// 64bits
			break;
		default:
			// array
			// objects
			// bad characters
			return NULL;
			break;
	}
}

static int check_return_idx(MethodIds *method)
{
	int idx;	
	if(method == NULL)
		return -1;

	if(dex_header == NULL)
		process_dex_header();
	if(proto_ids == NULL)
		process_proto_ids();
	if(type_ids == NULL)
		process_type_ids();

	idx = method->proto_idx;
	if(idx > dex_header->protoIdsSize){
		return -1;
	}

	idx = proto_ids[idx].return_type_idx;
	if(idx > dex_header->typeIdsSize){
		return -1;
	}

	idx = type_ids[idx].descriptor_idx;
	if(idx > dex_header->stringIdsSize){
		return -1;
	}

	return idx;
}

static int process_type(char *buffer, size_t len, u4 idx)
{
	// idx is string ids index which contains type strings.
	const char *type;
	int i;
	int cnt = 0;
	int str_idx = 0;
	int array_depth = 0;


	if(str_ids == NULL)
		process_string_ids();

	if(str_ids[idx][str_idx] == '['){
		// array
		do{
			++array_depth;
		}while(str_ids[idx][++str_idx] == '[');
	}

	if(str_ids[idx][str_idx] == 'L'){
		// objects
		cnt += snprintf(buffer, len, "%s", &str_ids[idx][++str_idx]);
		// remove object's ';' character
		buffer[--cnt] = '\0';

		// change '/' to '.' for objects
		for(i = 0; buffer[i] != '\0'; ++i){
			if(buffer[i] == '/')
				buffer[i] = '.';
		}
	}else{
		if((type = trans_dex_type_name(str_ids[idx][str_idx])) == NULL){
			fprintf(stderr, "process_type - bad type character '%c'.\n", str_ids[idx][str_idx]);
			memset(buffer, 0, len);
			return -1;
		}
		cnt = snprintf(buffer, len, "%s", trans_dex_type_name(str_ids[idx][str_idx]));
	}

	for(i = 0; i < array_depth; ++i){
		cnt += snprintf(buffer+cnt, len-cnt, "[]");
	}

	return cnt;
}

static int check_name_idx(MethodIds *method)
{
	int idx;
	if(method == NULL){
		return -1;
	}

	if(dex_header == NULL)
		process_dex_header();

	idx = method->name_idx;
	if(idx > dex_header->stringIdsSize)
		return -1;
	return idx;
}

static int _get_type_list(char *buffer, size_t len, int offset)
{
	int i;
	int cnt = 0;
	TypeList tl;
	if(dex == NULL || buffer == NULL){
		fprintf(stderr, "_get_type_list - invalid FILE dex and/or buffer parameter.\n");
		return -1;
	}

	if(get_data(&tl.size, offset, sizeof(tl.size), 1, dex) == NULL){
		fprintf(stderr, "_get_type_list - get type item size failure.\n");
		return -1;
	}

	if(tl.size == 0)
		return 0;

	if(type_ids == NULL)
		process_type_ids();

	tl.type_items = (TypeListItem *)get_data(NULL, offset+sizeof(tl.size), sizeof(TypeListItem), tl.size, dex);
	if(tl.type_items == NULL){
		fprintf(stderr, "_get_type_list - get data type list failure.\n");
		free(tl.type_items);
		return -1;
	}

	for(i = 0; i < tl.size; ++i){
		cnt += process_type(buffer+cnt, len-cnt, type_ids[tl.type_items[i].type_idx].descriptor_idx);
		if(i != tl.size -1)
			cnt += snprintf(buffer+cnt, len-cnt, ", ");
	}

	return cnt;
}

static int process_method_paras(char *buffer, size_t len, int offset)
{
	int cnt = 0;
	int ret;

	if(buffer == NULL){
		fprintf(stderr, "process_method_paras - invalid buffer parameter.\n");
		return -1;
	}

	cnt += snprintf(buffer+cnt, len-cnt, "(");

	if((ret = _get_type_list(buffer+cnt, len-cnt, offset)) == -1){
		fprintf(stderr, "process_method_paras - get type list failure.\n");
		return -1;
	}

	cnt += ret;
	cnt += snprintf(buffer+cnt, len-cnt, ")\n");

	return cnt;	
}

static char *process_method_item(MethodIds *method, int has_class_name)
{
	int idx;
	int cnt = 0;
	static char buffer[BUFFLEN];

	if(method == NULL){
		fprintf(stderr, "process_method_item - invalid method argument.\n");
		return NULL;
	}

	// process method return type
	if((idx = check_return_idx(method)) == -1){
		fprintf(stderr, "process_method_item - invalid method return type index '%d'.\n", method->proto_idx);
		return NULL;
	}
	cnt = process_type(buffer, BUFFLEN, idx);

	if(has_class_name){
		if(class_defs == NULL)
			process_class_type();
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s->", get_class_name(&class_defs[method->class_idx]));
	}

	// process method name
	if((idx = check_name_idx(method)) == -1){
		fprintf(stderr, "process_method_item - invalid method return type index '%d'.\n", method->name_idx);
		return NULL;
	}
	if(str_ids == NULL)
		process_string_ids();
	cnt += snprintf(buffer+cnt, BUFFLEN-cnt, " %s", str_ids[method->name_idx]);

	// process method parameters
	// the proto index has been checked.
	// if parameters_off equal to 0, means no parameter.
	if(proto_ids == NULL)
		process_proto_ids();
	if(proto_ids[method->proto_idx].parameters_off != 0)
		cnt += process_method_paras(buffer+cnt, BUFFLEN-cnt, proto_ids[method->proto_idx].parameters_off);
	else
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "()\n");

#ifdef __debug__

	printf("[*] cnt = %d, buffer = %s\n", cnt, buffer);

#endif

	return buffer;
}

static void process_proto_ids(void)
{
	if(dex_header == NULL){
		process_dex_header();
	}

	if(proto_ids == NULL){
		proto_ids = (ProtoIds *)get_data(NULL, dex_header->protoIdsOff, sizeof(ProtoIds), dex_header->protoIdsSize, dex);
		if(proto_ids == NULL){
			fprintf(stderr, "process_proto_ids - get ProtoIds data failure.\n");
			return ;
		}
	}
}

static char *process_field_item(u4 idx, int has_class_name)
{
	static char buffer[BUFFLEN];
	int cnt = 0;
	//skip the class name

	if(dex_header == NULL)
		process_dex_header();
	if(type_ids == NULL)
		process_type_ids();

	// check if the idx is valid
	if(field_ids[idx].type_idx > dex_header->typeIdsSize){
		fprintf(stderr, "process_field_item - invalid idx for field's type.\n");
		return NULL;
	}

	if(field_ids[idx].name_idx > dex_header->stringIdsSize){
		fprintf(stderr, "process_field_item - invalid index for field's name.\n");
		return NULL;
	}
	// field type
	cnt += process_type(buffer+cnt, BUFFLEN-cnt, type_ids[field_ids[idx].type_idx].descriptor_idx);
	// field name
	snprintf(buffer+cnt, BUFFLEN-cnt, " %s", str_ids[field_ids[idx].name_idx]);

	return buffer;
}

static void process_field_ids(void)
{
	if(dex_header == NULL){
		process_dex_header();
	}

	if(field_ids == NULL){
		field_ids = (FieldIds *)get_data(NULL, dex_header->fieldIdsOff, sizeof(FieldIds), dex_header->fieldIdsSize, dex);
		if(field_ids == NULL){
			fprintf(stderr, "process_field_ids - get FieldIds data failure.\n");
			return ;
		}
	}

#if 0
	puts("Field:");
	for(i = 0; i < dex_header->fieldIdsSize; ++i)
		printf("%s\n", process_field_item(i, 0));
#endif
}

static void process_method_ids(int has_class_name)
{
	int i;

	if(dex_header == NULL){
		process_dex_header();
	}

	if(method_ids == NULL){
		method_ids = (MethodIds *)get_data(NULL, dex_header->methodIdsOff, sizeof(MethodIds), dex_header->methodIdsSize, dex);
		if(method_ids == NULL){
			fprintf(stderr, "process_method_ids - get MethodIds data failure.\n");
			return ;
		}
	}
	if(do_method_ids){
		puts("Methods:");
		for(i = 0; i < dex_header->methodIdsSize; ++i)
			printf("%s", process_method_item(&method_ids[i], has_class_name));
	}
}

static char *_get_class_name(u4 idx)
{
	// argument idx is the index of type.
	static char buffer[BUFFLEN];
	if(type_ids == NULL)
		process_type_ids();
	if(str_ids == NULL)
		process_string_ids();
	// check if the type is class type.
	if(str_ids[type_ids[idx].descriptor_idx][0] != 'L'){
		fprintf(stderr, "_get_class_name - type '%c' is not class type.\n", str_ids[type_ids[idx].descriptor_idx][0]);
	}

	if(process_type(buffer, BUFFLEN, type_ids[idx].descriptor_idx) != -1)
		return buffer;
	return NULL;
}

static char *get_class_name(ClassDefs *class)
{

	//process class name
	// check class name index is invalid or not.
	if(class == NULL){
		fprintf(stderr, "get_class_name - invalid ClassDefs parameter.\n");
		return NULL;
	}

	if(dex_header == NULL)
		process_dex_header();

	if(class->class_idx > dex_header->typeIdsSize){
		fprintf(stderr, "get_class_name - invalid class index %d.\n", class->class_idx);
		return NULL;
	}

	return _get_class_name(class->class_idx);
}

static char *_get_access_flags(int flags, int type)
{
	int i;
	static char buffer[BUFFLEN];
	int cnt = 0;

	for(i = 0; (afs[i].value != 0) && (flags != 0); ++i){
		if((flags & afs[i].value) != 0){
			if((type & afs[i].field) != 0){
				cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s ", afs[i].name);
			}else{
				continue;
			}
			flags &= ~afs[i].value;
		}
	}

	if(flags != 0){
		fprintf(stderr, "get_access_flags - invalid access flag value.\n");
		return NULL;
	}
	return buffer;
}

static char *get_access_flags(ClassDefs *class, int type)
{
	int flags;
	if(class == NULL){
		fprintf(stderr, "get_class_name - invalid ClassDefs parameter.\n");
		return NULL;
	}

	flags = class->access_flags;

	if((flags & access_flags_mask) == 0)
		return NULL;
	return _get_access_flags(flags, type);
}

static char *get_super_name(ClassDefs *class)
{
	if(class == NULL){
		fprintf(stderr, "get_super_name - invalid FILE dex parameter.\n");
		return NULL;
	}

	if(class->superclass_idx == 0)
		return NULL;
	return _get_class_name(class->superclass_idx);
}

static char *get_interfaces(ClassDefs *class)
{
	int i;
	TypeList tl;
	int cnt = 0;
	static char buffer[BUFFLEN];

	if(dex == NULL || class == NULL){
		fprintf(stderr, "get_interfaces - invalid FILE dex or/and ClassDefs class parameters.\n");
		return NULL;
	}

	if(class->interfaces_off == 0){
		// no interface
		return NULL;
	}

	if(get_data(&tl.size, class->interfaces_off, sizeof(tl.size), 1, dex) == NULL){
		fprintf(stderr, "get_interfaces - get interfaces size failure.\n");
		return NULL;
	}

	if(tl.size == 0){
		// no interfaces
		return NULL;
	}

	tl.type_items = (TypeListItem *)get_data(NULL, class->interfaces_off+sizeof(tl.size), sizeof(TypeListItem), tl.size, dex);

	if(tl.type_items == NULL){
		fprintf(stderr, "get_interfaces - get interfaces name failure.\n");
		return NULL;
	}

	for(i = 0; i < tl.size; ++i){
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s", _get_class_name(tl.type_items[i].type_idx));
		if(i != tl.size - 1)
			cnt += snprintf(buffer+cnt, BUFFLEN-cnt, ", ");
	}
	return buffer;
}

static char *process_source_idx(ClassDefs *class)
{
	if(class == NULL){
		fprintf(stderr, "process_source_idx - invalid ClassDefs class argument.\n");
		return NULL;
	}

	if(class->source_file_idx == NO_INDEX){
		return NULL;
	}
	if(str_ids == NULL)
		process_string_ids();

	return str_ids[class->source_file_idx];
}

static char *process_annotation(ClassDefs *class)
{
	return NULL;
}

static char *process_encode_field(int idx, int flags)
{
	int cnt = 0;
	static char buffer[BUFFLEN];

	cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s", _get_access_flags(flags, FIELD));

	cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s;\n", process_field_item(idx, 0));

	return buffer;
	
}

static char *process_encode_method(int idx, int flags, int code_off)
{
	int cnt = 0;
	static char buffer[BUFFLEN];
	if(method_ids == NULL)
		process_method_ids(0);

	//char *process_method_item(FILE *dex, MethodIds *method, int has_class_name)
	cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s", _get_access_flags(flags, METHOD));

	cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "%s", process_method_item(&method_ids[idx], 0));

	return buffer;
}

static char *process_class_data(ClassDefs *class)
{
	static char buffer[BUFFLEN];
	ClassData class_data;
	unsigned int offset;
	int idx_diff = 0;
	int cnt = 0;
	int access_flags;
	int code_off;
	int i;

	if(class == NULL){
		fprintf(stderr, "process_class_data - invalid ClassDefs class parameter.\n");
		return NULL;
	}

	if(class->class_data_off == 0){
		printf("class_data_off = %d\n", class->class_data_off);
		// no class data, maybe a marker interface
		return NULL;
	}

	offset = class->class_data_off;
	class_data.static_fields_size = readUnsignedLeb128(dex, &offset);
	class_data.instance_fields_size = readUnsignedLeb128(dex, &offset);
	class_data.direct_methods_size = readUnsignedLeb128(dex, &offset);
	class_data.virtual_methods_size = readUnsignedLeb128(dex, &offset);

#ifdef __debug__
	printf("static_fields_size = %d, instance_fields_size = %d, "
			"direct_methods_size = %d, virtual_methods_size = %d\n", 
			class_data.static_fields_size, class_data.instance_fields_size, 
			class_data.direct_methods_size, class_data.virtual_methods_size);
#endif

	// static field
	if(class_data.static_fields_size != 0){
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "  Static Field:\n");
		for(i = 0; i < class_data.static_fields_size; ++i){
			idx_diff += readUnsignedLeb128(dex, &offset);
			access_flags = readUnsignedLeb128(dex, &offset);
			cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "    %s", process_encode_field(idx_diff, access_flags));
		}
	}

	// instance field
	if(class_data.instance_fields_size != 0){
		idx_diff = 0;
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "  Instance Field:\n");
		for(i = 0; i < class_data.instance_fields_size; ++i){
			idx_diff += readUnsignedLeb128(dex, &offset);
			access_flags = readUnsignedLeb128(dex, &offset);
			cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "    %s", process_encode_field(idx_diff, access_flags));
		}
	}

	// direct method
	if(class_data.direct_methods_size != 0){
		idx_diff = 0;
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "  Direct Method:\n");
		for(i = 0; i < class_data.direct_methods_size; ++i){
			idx_diff += readUnsignedLeb128(dex, &offset);
			access_flags = readUnsignedLeb128(dex, &offset);
			code_off = readUnsignedLeb128(dex, &offset);
			cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "    %s", process_encode_method(idx_diff, access_flags, code_off));
		}
	}

	// virtual method
	if(class_data.virtual_methods_size != 0){
		idx_diff = 0;
		cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "  Virtual Method:\n");
		for(i = 0; i < class_data.direct_methods_size; ++i){
			idx_diff += readUnsignedLeb128(dex, &offset);
			access_flags = readUnsignedLeb128(dex, &offset);
			code_off = readUnsignedLeb128(dex, &offset);
			cnt += snprintf(buffer+cnt, BUFFLEN-cnt, "    %s", process_encode_method(idx_diff, access_flags, code_off));
		}
	}

	return buffer;
}

static void process_class_items(ClassDefs *class)
{
	char *name;
	char *flag;
	char *super;
	char *interfaces;
	char *src;
	char *class_data;
	//process class name
	// check class name index is invalid or not.
	if(class == NULL){
		fprintf(stderr, "process_class_items - invalid ClassDefs parameter.\n");
		return ;
	}
	name = get_class_name(class);
	if(name != NULL)
		printf(" name: %s\n", name);

	flag = get_access_flags(class, CLASS);
	if(flag != NULL)
		printf(" flag: %s\n", flag);

	super = get_super_name(class);
	if(super != NULL){
		printf(" super: %s\n", super);
	}

	interfaces = get_interfaces(class);
	if(interfaces != NULL){
		printf(" interface: %s\n", interfaces);
	}
	src = process_source_idx(class);
	if(src != NULL){
		printf(" source: %s\n", src);
	}

	class_data = process_class_data(class);
	if(class_data != NULL)
		printf(" class data: \n%s", class_data);
}

static void process_class_type(void)
{
	int i;
	if(dex_header == NULL){
		process_dex_header();
	}

	if(class_defs == NULL){
		class_defs = (ClassDefs *)get_data(NULL, dex_header->classDefsOff, sizeof(ClassDefs), dex_header->classDefsSize, dex);
		if(class_defs == NULL){
			fprintf(stderr, "process_class_type - get ClassDefs data failure.\n");
			return ;
		}
	}

	if(do_class_defs){
		if(class_name != NULL){
			for(i = 0; i < dex_header->classDefsSize; ++i){
				if(strcmp(class_name, get_class_name(&class_defs[i])) == 0)
					break;
			}
			if(i == dex_header->classDefsSize){
				fprintf(stderr, "process_class_type - not found class '%s'.\n", class_name);
				return ;
			}
			process_class_items(&class_defs[i]);
			class_name = NULL;
		}else{
			for(i = 0; i < dex_header->classDefsSize; ++i){
				printf("Class %d:\n", i);
				process_class_items(&class_defs[i]);
			}
		}
	}
#if 0
	puts("Class:");
	process_class_items(dex, &class_defs[0]);
#endif
}

static void parse_args(int argc, char **argv)
{
	int c;
	static struct option opts[] = {
		{"method", 0, NULL, 'm'},
		{"class", 1, NULL, 'c'},
		{"Class", 0, NULL, 'C'},
		{"header", 0, NULL, 'H'},
		{"strings", 0, NULL, 's'},
		{"help", 0, NULL, 'h'},
		{"all", 0, NULL, 'a'},
		{0, 0, 0, 0},
	};	
	static const char *const short_options = "mc:CHsh";
	while((c = getopt_long(argc, argv, short_options, opts, NULL)) != -1){
		switch(c){
			case 'm':
				do_method_ids = 1;	
				break;
			case 'c':
				do_class_defs = 1;
				class_name = optarg;
				puts(class_name);
				break;
			case 'C':
				do_class_defs = 1;
				break;
			case 'H':
				do_dex_header = 1;
				break;
			case 's':
				do_string_ids = 1;
				break;
			case 'h':
				do_help = 1;
				break;
			case 'a':
				do_dex_header = 1;
				do_string_ids = 1;
				do_class_defs = 1;
				break;
			default:	
				// get invalid opt will print usage and exit.
				do_help = 1;
		}
	}

	if(optind == 1){
		// no options
		do_dex_header = 1;
		do_string_ids = 1;
		do_class_defs = 1;
	}

	if(optind >= argc){
		usage();
		exit(EXIT_FAILURE);
	}
}

static void process_file(const char *file)
{
	struct stat st;
	if(file == NULL)
		return ;
	if(stat(file, &st) == -1){
		fprintf(stderr, "stat file '%s' failure.\n", file);
		return ;
	}

	if(!S_ISREG(st.st_mode)){
		fprintf(stderr, "%s is not a regular file.\n", file);
		return ;
	}

	dex = fopen(file, "rb");
	if(dex == NULL){
		perror("open file failre: ");
		return ;
	}

	if(do_dex_header)
		process_dex_header();

	if(do_string_ids)
		process_string_ids();

	if(do_class_defs){
		do_method_ids = 0;
		process_class_type();
	}

	if(do_method_ids)
		process_method_ids(1);

	if(do_help)
		usage();

	// process file.
}

int main(int argc, char **argv)
{
	// print basic program prompt information
	printf("\n=== %s %s ===\n\n", PROGRAM_NAME, PROGRAM_VER);

	parse_args(argc, argv);

	while(optind < argc)
		process_file(argv[optind++]);

#if 0

	if(argc < 2){
		usage();
		exit(EXIT_FAILURE);
	}

	dex = fopen(argv[1], "rb");
	if(dex == NULL){
		die("open file %s", argv[1]);
	}

	do_dex_header++;
	do_string_ids++;
	do_type_ids++;
	process_dex_header(dex);
	process_string_ids(dex);
	process_type_ids(dex);
	process_proto_ids(dex);
	process_method_ids(dex);
	//process_annotation(dex);
	process_class_type(dex);
	process_field_ids(dex);
#endif

	return 0;
}
