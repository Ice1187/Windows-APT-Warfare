#include <Windows.h>
#include <stdio.h>
 
#define getNtHdrs(pe) ((IMAGE_NT_HEADERS*)((size_t)pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew))
#define getSectArr(pe) ((IMAGE_SECTION_HEADER*)((char*)(getNtHdrs(pe)) + sizeof(IMAGE_NT_HEADERS)))
 
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
 
size_t rva2Offset(char* pe, size_t rva) {
    IMAGE_SECTION_HEADER* sectHdrs = getSectArr(pe);
    for(int i = 0; i < getNtHdrs(pe)->FileHeader.NumberOfSections; i++) {
        if (rva >= sectHdrs[i].VirtualAddress &&
            rva < sectHdrs[i].VirtualAddress + sectHdrs[i].Misc.VirtualSize) {
                return rva - sectHdrs[i].VirtualAddress + sectHdrs[i].PointerToRawData;
            }
    }
    fputs("rva2Offset not found", stderr);
    return 0;
}
 
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fputs("./peExportParser.exe target.dll", stderr);
        return 1;
    }
 
    long  pe_size;
    char* pe;
    readPE(argv[1], &pe, &pe_size);
 
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(pe + rva2Offset(pe, getNtHdrs(pe)->OptionalHeader.DataDirectory[0].VirtualAddress));
    size_t numOfNames = exportDir->NumberOfNames;
    size_t numOfFuncs = exportDir->NumberOfFunctions;
    printf("Parsing DLL module: %s\n", (char*)(pe + rva2Offset(pe, exportDir->Name)));
    printf("Number of export functions: %d\n", numOfFuncs);
    printf("Number of export functions with name: %d\n", numOfNames);
 
    char* name;
    WORD ordinal;
    size_t rva;
    printf("Export Functions:\n");
    for(int i = 0; i < numOfNames; i++) {
        name = (char*)(pe + rva2Offset(pe, ((DWORD*)(pe + rva2Offset(pe, exportDir->AddressOfNames)))[i]));
        ordinal = ((WORD*)(pe + rva2Offset(pe, exportDir->AddressOfNameOrdinals)))[i];
        rva = (size_t)(((DWORD*)(pe + rva2Offset(pe, exportDir->AddressOfFunctions)))[ordinal]);
 
        printf("  #%hx - %s @ %x\n", ordinal, name, rva);
    }
 
    return 0;
}
