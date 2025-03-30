#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;  //重新定义数据类型赋予意义

//定义结构数据
//DOS头结构体
typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	long e_lfanew;
}IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

//NT头文件头结构体
typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
}IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

//NT头可选头结构体
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;           // 魔术数字
    BYTE MajorLinkerVersion; // 链接器主版本号
    BYTE MinorLinkerVersion; // 链接器次版本号
    DWORD SizeOfCode;        // 代码段大小
    DWORD SizeOfInitializedData; // 已初始化数据段大小
    DWORD SizeOfUninitializedData; // 未初始化数据段大小
    DWORD AddressOfEntryPoint; // 入口点地址
    DWORD BaseOfCode;        // 代码段基地址
    DWORD BaseOfData;        // 数据段基地址
    DWORD ImageBase;         // 映像基地址
    DWORD SectionAlignment;  // 节对齐
    DWORD FileAlignment;     // 文件对齐
    WORD MajorOperatingSystemVersion; // 操作系统主版本号
    WORD MinorOperatingSystemVersion; // 操作系统次版本号
    WORD MajorImageVersion; // 映像主版本号
    WORD MinorImageVersion; // 映像次版本号
    WORD MajorSubsystemVersion; // 子系统主版本号
    WORD MinorSubsystemVersion; // 子系统次版本号
    DWORD Win32VersionValue; // Win32 版本值
    DWORD SizeOfImage;       // 映像大小
    DWORD SizeOfHeaders;     // 头文件大小
    DWORD CheckSum;          // 校验和
    WORD Subsystem;       // 子系统类型
    WORD DllCharacteristics; // DLL 特征
    DWORD SizeOfStackReserve; // 栈保留大小
    DWORD SizeOfStackCommit; // 栈提交大小
    DWORD SizeOfHeapReserve; // 堆保留大小
    DWORD SizeOfHeapCommit; // 堆提交大小
    DWORD LoaderFlags;       // 加载器标志
    DWORD NumberOfRvaAndSizes; // RVA 和大小的数量
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

// NT 头结构体
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;         // 签名，固定为 0x00004550
    IMAGE_FILE_HEADER FileHeader;   // 文件头
    IMAGE_OPTIONAL_HEADER OptionalHeader; // 可选头
} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

// 节表结构体
typedef struct _IMAGE_SECTION_HEADER {
    char Name[8];                   // 节名
    DWORD VirtualSize;       // 虚拟大小
    DWORD VirtualAddress;    // 虚拟地址
    DWORD SizeOfRawData;     // 原始数据大小
    DWORD PointerToRawData;  // 原始数据指针
    DWORD PointerToRelocations; // 重定位指针
    DWORD PointerToLinenumbers; // 行号指针
    WORD NumberOfRelocations; // 重定位数量
    WORD NumberOfLinenumbers; // 行号数量
    DWORD Characteristics;   // 节特征
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

//模拟堆内存块结构体
typedef struct MemoryBlock{
	size_t size;
    int is_free;
	struct MemoryBlock* next;
}MemoryBlock;

//内存管理模块
//初始化内存池
//使用malloc函数分配一块连续的内存空间作为内存池
MemoryBlock* init_memory_pool(size_t pool_size) {     //对象大小和分配的内存池大小
	MemoryBlock* pool = (MemoryBlock*)malloc(pool_size);
	if (pool == NULL) {
		return NULL;
	}
	pool->size = pool_size - sizeof(MemoryBlock);
	pool->is_free = 1;   //1表示内存块空闲
	pool->next = NULL;
    return pool;
}

//模拟内存分配
//模拟内存释放