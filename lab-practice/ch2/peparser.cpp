#include <stdio.h>
#include <Windows.h>

void peparser(char* pe) {
    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS*)((size_t)dosHdr + dosHdr->e_lfanew);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fputs("DOS or NT signature error", stderr);
        return;
    }

    if (auto optHdr = &ntHdrs->OptionalHeader) {
        printf("ImageBase: %p\n", optHdr->ImageBase);
        printf("AOE: %p\n", optHdr->ImageBase + optHdr->AddressOfEntryPoint);
        printf("Dynamic Memory Usage: %x\n", optHdr->SizeOfImage);
    }

    IMAGE_SECTION_HEADER* sectHdr = (IMAGE_SECTION_HEADER*)((size_t)ntHdrs + sizeof(*ntHdrs));
    for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++) {
        printf("\t#%.2x - %8s - %.8x  - %.8x \n", i, \
            sectHdr[i].Name, sectHdr[i].PointerToRawData, sectHdr[i].SizeOfRawData);
    }
}

int main(int argc, char* argv[]) {
    FILE* pFile;
    long lSize;
    char* buf;
    size_t result;

    // Read PE file
    printf("Target Exe: %s\n", argv[1]);
    pFile = fopen(argv[1], "rb");
    if (pFile == NULL) {fputs("fopen error", stderr); return 1;}

    fseek(pFile, 0, SEEK_END);
    lSize = ftell(pFile);
    rewind(pFile);

    buf = (char*) malloc(sizeof(char)*lSize);
    if (buf == NULL) {fputs("malloc error", stderr); return 1;}

    result = fread(buf, 1, lSize, pFile);
    if (result != lSize) {fputs("fread error", stderr); return 1;}

    // peParser
    peparser(buf);


    fclose(pFile);
    free(buf);
    return 0;
}
