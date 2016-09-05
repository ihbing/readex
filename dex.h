#ifndef __DEX_H__
#define __DEX_H__

#include "dextypes.h"

/* SHA-1 code length */
#define kSHA1DigestLen	20

typedef struct {
	u1	magic[8];			/* dex magic number, its value is "dex\n035\x0" */
	u4 	checksum;			/* adler32 algorithm */
	u1	signature[kSHA1DigestLen];
	u4	fileSize;
	u4	headerSize;
	u4	endianTag;
	u4	linkSize;
	u4	linkOff;
	u4	mapOff;
	u4	stringIdsSize;
	u4	stringIdsOff;
	u4	typeIdsSize;
	u4	typeIdsOff;
	u4	protoIdsSize;
	u4	protoIdsOff;
	u4	fieldIdsSize;
	u4	fieldIdsOff;
	u4	methodIdsSize;
	u4	methodIdsOff;
	u4	classDefsSize;
	u4	classDefsOff;
	u4	dataSize;
	u4	dataOff;
} DexHeader;

enum {
	kDexTypeHeaderItem				= 0x0000,
	kDexTypeStringIdItem			= 0x0001,
	kDexTypeTypeIdItem				= 0x0002,
	kDexTypeProtoIdItem				= 0x0003,
	kDexTypeFieldIdItem				= 0x0004,
	kDexTypeMethodIdItem			= 0x0005,
	kDexTypeClassDefItem			= 0x0006,
	kDexTypeMapList					= 0x1000,
	kDexTypeTypeList				= 0x1001,
	kDexTypeAnnotationSetRefList	= 0x1002,
	kDexTypeAnnotationSetItem		= 0x1003,
	kDexTypeClassDataItem			= 0x2000,
	kDexTypeCodeItem				= 0x2001,
	kDexTypeStringDataItem			= 0x2002,
	kDexTypeDebugInfoItem			= 0x2003,
	kDexTypeAnnotationItem 			= 0x2004,
	kDexTypeEncodedArrayItem		= 0x2005,
	kDexTypeAnnotationDirectoryItem	= 0x2006,
};

enum {
	ACC_PUBLIC						= 0x00000001,		// class, field method, ic
	ACC_PRIVATE						= 0x00000002,		// field, method, ic
	ACC_PROTECTED					= 0x00000004,		// field, method, ic
	ACC_STATIC						= 0x00000008,		// field, method, ic
	ACC_FINAL						= 0x00000010,		// class, field, method, ic
	ACC_SYNCHRONIZED				= 0x00000020,		// method (only allowed on natives)
	ACC_SUPER						= 0x00000020,		// class (not used in Dalvik)
	ACC_VOLATILE					= 0x00000040,		// field
    ACC_BRIDGE       				= 0x00000040,       // method (1.5)  
    ACC_TRANSIENT					= 0x00000080,       // field  
    ACC_VARARGS						= 0x00000080,       // method (1.5)  
    ACC_NATIVE						= 0x00000100,       // method  
    ACC_INTERFACE					= 0x00000200,       // class, ic  
    ACC_ABSTRACT					= 0x00000400,       // class, method, ic  
    ACC_STRICT						= 0x00000800,       // method  
    ACC_SYNTHETIC					= 0x00001000,       // field, method, ic  
    ACC_ANNOTATION					= 0x00002000,       // class, ic (1.5)  
    ACC_ENUM						= 0x00004000,       // class, field, ic (1.5)  
    ACC_CONSTRUCTOR					= 0x00010000,       // method (Dalvik only)  
    ACC_DECLARED_SYNCHRONIZED 		= 0x00020000,       // method (Dalvik only)  
};

enum {
	METHOD 			= 0x1,
	FIELD 			= 0x2,
	CLASS 			= 0x3,
};

typedef struct {
	int value;
	int field;
	const char *name;
}AccessFlags;

typedef struct {
	u4	string_data_off;
}StringIdItem;

typedef struct {
	u4 descriptor_idx;
}TypeIdIndex;

typedef struct {
	u4 shorty_idx;		// a short format of method. return type and parameters
	u4 return_type_idx;
	u4 parameters_off;
}ProtoIds;

typedef struct {
	u2 type_idx;
}TypeListItem;

typedef struct {
	u4 size;
	TypeListItem *type_items;
}TypeList;

typedef struct {
	u2 class_idx;
	u2 type_idx;
	u4 name_idx;
}FieldIds;

typedef struct {
	u2 class_idx;
	u2 proto_idx;
	u4 name_idx;
}MethodIds;

typedef TypeList FieldAnnotat;
typedef TypeList MethodAnnotat;
typedef TypeList ParaAnnotat;

typedef struct {
	u4 class_annotations_off;
	u4 fields_size;
	u4 annotated_methods_size;
	u4 annotated_parameters_size;
}AnnotationsDirItem;

typedef struct {
	int static_fields_size;
	int instance_fields_size;
	int direct_methods_size;
	int virtual_methods_size;
}ClassData;

typedef struct {
	u4 class_idx;
	u4 access_flags;
	u4 superclass_idx;
	u4 interfaces_off;
	u4 source_file_idx;
	u4 annotations_off;
	u4 class_data_off;
	u4 static_value_off;
}ClassDefs;

typedef struct {
	u2	type;
	u2	unused;				// unused, for paddings
	u4	size;
	u4	offset;
} DexMapItem;

typedef struct {
	u4	size;
	DexMapItem list[1];
} DexMapList;

#endif	/* __DEX_H__ */