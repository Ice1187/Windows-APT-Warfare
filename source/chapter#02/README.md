# Ch.2 of [《Windows APT Warfare：惡意程式前線戰術指南》](https://github.com/aaaddress1/Windows-APT-Warfare)

### Portable Executable File

- DOS Header (IMAGE_DOS_HEADER)
    - `.e_magic`: The magic number of the DOS header, always defined as `MZ`
    - `.e_lfanew`: Point to the RVA of NT Header
        - **L**ong **F**ile **A**ddress for the **NEW** Executable (unofficial)
- NT Header ([IMAGE_NT_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64))
    - `.Signature`: The magic number of the NT header, always defined as `PE\x00\x00`
    - `.FileHeader`: Assembler 產生的 COFF 檔案檔頭
        - `.Machine`: x86, x64, ARM, or other architecture
        - `.NumberOfSection`: Number of sections
        - `.TimeDataStamp`: The timestamp of compilation
        - `.SizeOfOptionalHeader`: The size of Optional Header in the file, usually 0xE0 (320bit) or 0xF0 (64-bit)
        - `.Characteristics`: Other properties of the PE module, ex: 32 bit, DLL, redirect info...
    - `.OptionalHeader`: The additional info added by linker so that the loader can load the file correctly
        - `.ImageBase`: The base (start) virtual address the PE module should be loaded to
        - `.SizeOfImage`: The needed size in the memory for the image to be loaded
        - `.SizeOfHeaders`: The needed size in the memory for all the headers (DOS, NT, Section) to be loaded
        - `.AddressOfEntryPoint` (AOE): The entry of the program, usually point to the function in the `.text` section
        - `.FileAlignment`: The alignment of the section size in the file, usually 0x200 = 512 bytes
            - The bytes of `FileAlignment` should fit the blocksize of most filesystems
        - `.SectionAlignment`: The alignment of the section size in the memory, usually 0x1000 = 4096 bytes
            - The bytes of `SectionAlignment` should fit the size of a memory page
    - `.DataDirectory`: Record the start and the size of 15 struct that PE might use
        - Export Directory 導出表
        - Import Directory 導入表
        - Base Relocation Table 重定位表
        - Import Address Table 全域導入函數指針表
        - Security Directory 數位簽署 Authenticode 結構表
        - ...
    - 備註
        - NT Header 後方緊接著 Section 陣列
        - NT Header 的大小是固定的，因此每個 PE file 加上 sizeof(DOS_header) + sizeof(NT_header) 就會是 Section 陣列的開頭
- Section Header ([IMAGE_SECTION_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header))
    - `.Name`: The name of the section
    - `.PointerToRawData`: The offset of the file to the start of the raw data stored in this section
    - `.SizeOfRawData`: The size of the raw data of this section in the file
    - `.VirtualAddress`: The RVA of the section in the memory, relative to `ImageBase`
        - `ImageBase` + `VirtualAddress` = The start virtual address of the section in the memory
    - `.VirtualSize`: The needed size in the memory for the section to be loaded
    - `.Charateristics`: Other properties of the section, ex: permission
    - 備註
        - `.text`, `.data`, `.idata` 等 section header 串成一個 Section Header array
        - Section Header array 之後才是緊接著各 section 的 raw data
- Raw Data of Each Section
- 備註
    - 計算檔案大小
        - 最後一個 section 的 `PointerToRawData` + `SizeOfRawData` 等於使用 `GetFileSize()` Win API 得到的 file size (未進行 align?)
        - 該檔案在 Filesystem 內的實際大小為下列二者相加：
            - sizeof(`DOS_Header`) + sizeof(`NT_Header`) + sizeof(`Section_Header`) * `NumberOfSections`，前面總和再跟 `FileAlignment` round up 的大小
            - 每個 section 跟 `FileAlignment` round up 之後相加的和
    - `SizeOfRawData` v.s. `VirtualSize`
        - `SizeOfRawData` 和 `VirtualSize` 分別為 file/memory 中 data 的大小
        - 若所有全域變數皆為 assign 初始值，則會出現 `SizeOfRawData` 為 0，`VirtualSize` 不為 0 的狀況。

---

### Load into Memory

1. 從 NT Header → Optional Header → `ImageBase` 得到預期的虛擬記憶體位址起點。
    - 若有開 ASLR 與重定位功能，則可能是一定範圍內的隨機位址
2. 從 NT Header → Optional Header → `SizeOfImage` 得知所需的記憶體空間，並依此申請相對應的空間大小，Ex: 0xDEAD bytes。
3. 從 NT Header → Optional Header → `SizeOfHeaders` 得知全部 headers 的總和大小 (DOS + NT + Sections)，並將 file offset = `0` ~ `SizeOfHeaders` 的資料全部 copy 至 virtual address `ImageBase + 0` ~ `ImageBase + SizeOfHeaders`。
4. 從 NT Header → File Header → `SizeOfSections` 得知 section array 的長度，然後 loop 過所有 section header，並依其中記載的內容將 `PointerToRawData` ~ `PointerToRawData + SizeOfRawData` 的資料 load 到 virtual address `ImageBase + VirtualAddress` 上。
5. 全部 section 都 load 進 memory 後，loader 便開始進行修正，然後跳到 `AddressOfEntryPoint` 開始執行。
指南》

---

### PE 蠕蟲感染 (PE Patcher)

> *蠕蟲不需要附在別的程式內，可能不用使用者介入操作也能自我複製或執行。
                                                                                                                      — From [Wikipedia 電腦蠕蟲](https://zh.wikipedia.org/wiki/電腦蠕蟲)*

作者提供的 shellcode 彈不出 messagebox，換了一個彈 calculator 的。

Source code: `PE_Patcher/PE_Patcher.cpp`
