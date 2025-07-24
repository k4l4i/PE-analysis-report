#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

void ParsePEFile(const char* testfile);
int main() {
    const char* filePath = "test.exe"; 
    ParsePEFile(filePath);//解析文件函数
    return 0;
}
void ParsePEFile(const char* testfile) {
    //句柄处理文件
    HANDLE hFile = CreateFileA(testfile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("无法打开文件: %s\n", testfile);
        return;
    }

    // 获取文件大小
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("无法获取文件大小\n");
        CloseHandle(hFile);
        return;
    }

    // 分配内存用于数据读取
    LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (fileBuffer == NULL) {
        printf("无法分配内存\n");
        CloseHandle(hFile);
        return;
    }
    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        printf("无法读取文件内容\n");
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return;
    }

    // 关闭文件句柄
    CloseHandle(hFile);

    // 检查DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("不是有效的DOS头\n");
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return;
    }

    // 获取NT头
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("不是有效的NT头\n");
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return;
    }

    // 打印基本信息
    printf("PE文件基本信息:\n");
    printf("  入口点RVA: 0x%X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("  镜像基址: 0x%X\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("  节表数量: %d\n", pNtHeaders->FileHeader.NumberOfSections);

    // 获取节表
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        printf("  节表 %d:\n", i + 1);
        printf("    名称: %s\n", pSectionHeader[i].Name);
        printf("    虚拟大小: 0x%X\n", pSectionHeader[i].Misc.VirtualSize);
        printf("    虚拟地址: 0x%X\n", pSectionHeader[i].VirtualAddress);
        printf("    大小: 0x%X\n", pSectionHeader[i].SizeOfRawData);
        printf("    指针: 0x%X\n", pSectionHeader[i].PointerToRawData);
    }

    // 释放内存
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
}

