#include <stdio.h>
#include <Windows.h>
 
// shellcode source: https://www.exploit-db.com/shellcodes/48116
char SHELLCODE[] = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";
#define fileAlign 0x200
#define sectAlign 0x1000
 
#define getNtHdrs(pe) ((IMAGE_NT_HEADERS*)((size_t)pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew))
#define alignUp(size, align) (((size) / (align) + 1) * (align))
 
int writeFile(const char* path, char* pe, long size) {
    FILE* pFile;
    size_t result;
 
    printf("Target File: %s\n", path);
    pFile = fopen(path, "wb");
    if (pFile == NULL) {fputs("fopen error", stderr); return 1;}
 
    result = fwrite(pe, 1, size, pFile);
    if (result != size) {fputs("fwrite error", stderr); return 1;}
 
    fclose(pFile);
    return 0;
}
 
int main(void) {
    size_t hdrsSize = alignUp(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), fileAlign);
    size_t dataSize = alignUp(sizeof(SHELLCODE), fileAlign);
    size_t fileSize = hdrsSize + dataSize;
    char* pe;
 
    pe = (char*)calloc(fileSize, 1);
    if (pe == NULL) {fputs("calloc error", stderr); return 1;}
 
    // dos header
    ((IMAGE_DOS_HEADER*)pe)->e_magic = IMAGE_DOS_SIGNATURE;
    ((IMAGE_DOS_HEADER*)pe)->e_lfanew = sizeof(IMAGE_DOS_HEADER);
 
    // File header
    getNtHdrs(pe)->Signature = IMAGE_NT_SIGNATURE;
    getNtHdrs(pe)->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    getNtHdrs(pe)->FileHeader.NumberOfSections = 1;
    getNtHdrs(pe)->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    getNtHdrs(pe)->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
 
    // Section header and data
    IMAGE_SECTION_HEADER* sectHdr = (IMAGE_SECTION_HEADER*)((size_t)pe + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS));
    memcpy(sectHdr->Name, "ice1187\x00", 8);
    sectHdr->Misc.VirtualSize = sectAlign;
    sectHdr->VirtualAddress = alignUp(hdrsSize, sectAlign);
    sectHdr->SizeOfRawData = sizeof(SHELLCODE);
    sectHdr->PointerToRawData = hdrsSize;
    sectHdr->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
 
    // Optional header
    getNtHdrs(pe)->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
    getNtHdrs(pe)->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;
    getNtHdrs(pe)->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress;
    getNtHdrs(pe)->OptionalHeader.ImageBase = 0x400000;
    getNtHdrs(pe)->OptionalHeader.SectionAlignment = sectAlign;
    getNtHdrs(pe)->OptionalHeader.FileAlignment = fileAlign;
    getNtHdrs(pe)->OptionalHeader.SizeOfImage = alignUp(hdrsSize, sectAlign) + alignUp(dataSize, sectAlign);
    getNtHdrs(pe)->OptionalHeader.SizeOfHeaders = hdrsSize;
    getNtHdrs(pe)->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    getNtHdrs(pe)->OptionalHeader.MajorSubsystemVersion = 5;
    getNtHdrs(pe)->OptionalHeader.MinorSubsystemVersion = 1;
 
    // section data
    memcpy(pe + hdrsSize, SHELLCODE, sizeof(SHELLCODE));
 
    writeFile("tinyPE.exe", pe, fileSize);
 
    free(pe);
    return 0;
}
