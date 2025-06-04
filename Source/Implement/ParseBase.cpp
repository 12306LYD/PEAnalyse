
#include"ParseBase.h"


#include <iomanip>
#include <algorithm>



ParseBase::ParseBase()
{
    m_FileType = 0;
    m_pFileBuff = NULL;
    m_FileSize = 0;
    m_FilePath = L"";
}

ParseBase::~ParseBase()
{
}

bool ParseBase::InitFileInfo(std::wstring FilePath)
{
    
    m_FileType = Utils::FileInfoCheck(FilePath);
    if (m_FileType!= FILE_TYPE_X86_PE&& m_FileType!= FILE_TYPE_X64_PE)
    {
        std::wcout << FilePath << L"初始化失败,未知的文件格式" << std::endl;
        return false;
    }
	//打开文件文件并读取文件内容到
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwFileSize = 0;
    DWORD dwBytesRead = 0;
    // 打开文件
    hFile = CreateFileW(
        FilePath.c_str(),               
        GENERIC_READ,             // 访问模式 - 只读
        FILE_SHARE_READ,          // 共享模式 - 允许其他进程读取
        NULL,                     // 安全属性 - 默认
        OPEN_EXISTING,            // 创建方式 - 必须存在
        FILE_ATTRIBUTE_NORMAL,    // 文件属性
        NULL                      // 模板文件 - 无
    );
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        wprintf(L"无法打开文件: %s, 错误代码: %d\n", FilePath.c_str(), GetLastError());
        return FALSE;
    }
    // 获取文件大小
    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        wprintf(L"获取文件大小失败, 错误代码: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    // 分配内存
    m_pFileBuff = new BYTE[dwFileSize]{};
    if (m_pFileBuff == NULL) {
        wprintf(L"内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }
    // 读取文件内容
    if (!ReadFile(hFile, m_pFileBuff, dwFileSize, &dwBytesRead, NULL))
    {
        wprintf(L"读取文件失败, 错误代码: %d\n", GetLastError());
        delete []m_pFileBuff;
        m_pFileBuff = NULL;
        CloseHandle(hFile);
        return FALSE;
    }
    // 检查读取的字节数是否匹配
    if (dwBytesRead != dwFileSize)
    {
        wprintf(L"读取的字节数不匹配\n");
        delete[]m_pFileBuff;
        m_pFileBuff = NULL;
        CloseHandle(hFile);
        return FALSE;
    }
    // 返回结果
    m_FileSize = dwFileSize;
    // 关闭文件句柄
    CloseHandle(hFile);
    return TRUE;
}

void ParseBase::DatCollection()
{
    if (m_FileType != FILE_TYPE_X86_PE && m_FileType != FILE_TYPE_X64_PE)
    {
        std::wcout <<  L"数据信息获取失败,未知的文件格式" << std::endl;
        return ;
    }
    //获取dosHeader;
     m_pDosHeader = (IMAGE_DOS_HEADER*)m_pFileBuff;
    //获取ntHeader
     m_pNtHeader= Utils::GetPeNtheader(m_pFileBuff);
    //获取fileheader
     m_pFileHeader = (IMAGE_FILE_HEADER*)Utils::GetPeFileHeader(m_pFileBuff);
    //获取OptionalHeader
     m_pOptionalHeader = Utils::GetPeOptionalHeader(m_pFileBuff);
     if (m_FileType== FILE_TYPE_X64_PE)
     {
         IMAGE_OPTIONAL_HEADER64* pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
         m_DataDirectoryNum = pOptionalHeader->NumberOfRvaAndSizes;
         m_pDataDirectory = pOptionalHeader->DataDirectory;
     }
     else 
     {
         IMAGE_OPTIONAL_HEADER32* pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
         m_DataDirectoryNum = pOptionalHeader->NumberOfRvaAndSizes;
         m_pDataDirectory = pOptionalHeader->DataDirectory;
     }
     
     //获取sectionHeader
     m_pSectionHeaders = (IMAGE_SECTION_HEADER*)Utils::GetPeSectionHeader(m_pFileBuff);



     return;
}

void ParseBase::DataParse()
{
    if (m_FileType != FILE_TYPE_X86_PE && m_FileType != FILE_TYPE_X64_PE)
    {
        std::wcout << L"数据信息获取失败,未知的文件格式" << std::endl;
        return;
    }
     ParseDosHeader();
     ParseNtHeader();

     ParseDataDirectoryTable();

     ParseSectionHeaders();
 
    return;
}

void ParseBase::ParseDosHeader()
{
   
    // Print DOS header information
    std::cout << "DOS Header:" << std::endl;
    std::cout << "  Magic: 0x" << std::hex << m_pDosHeader->e_magic << std::dec << " (MZ)" << std::endl;
    std::cout << "  Bytes on last page: " << m_pDosHeader->e_cblp << std::endl;
    std::cout << "  Pages in file: " << m_pDosHeader->e_cp << std::endl;
    std::cout << "  Relocations: " << m_pDosHeader->e_crlc << std::endl;
    std::cout << "  Size of header in paragraphs: " << m_pDosHeader->e_cparhdr << std::endl;
    std::cout << "  PE Header offset: 0x" << std::hex << m_pDosHeader->e_lfanew << std::dec << std::endl;
    std::cout << "-----------------------------" << std::endl;

    return;
}

void ParseBase::ParseNtHeader()
{


    // Print NT header information
    std::cout << "NT Headers:" << std::endl;
    std::cout << "  Signature: 0x" << std::hex << ((PIMAGE_NT_HEADERS)m_pNtHeader)->Signature << std::dec << " (PE\\0\\0)" << std::endl;
    // Print File header information
    std::cout << "File Header:" << std::endl;
    std::cout << "  Machine: 0x" << std::hex << m_pFileHeader->Machine << std::endl;
    std::cout << "  Number of Sections: " << m_pFileHeader->NumberOfSections << std::endl;
    // Format timestamp
    char timeBuffer[32];
    time_t timestamp = static_cast<time_t>(m_pFileHeader->TimeDateStamp);
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::gmtime(&timestamp));
    std::cout << "  Time Date Stamp: " << m_pFileHeader->TimeDateStamp
        << " (" << timeBuffer << " UTC)" << std::endl;
    std::cout << "  Size of Optional Header: " << m_pFileHeader->SizeOfOptionalHeader << std::endl;
    std::cout << "  Characteristics: 0x" << std::hex << m_pFileHeader->Characteristics << std::dec << std::endl;

    // Print Optional header information

    if (m_FileType == FILE_TYPE_X64_PE)
    {
       
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
        std::cout << "Optional Header:" << std::endl;
        std::cout << "  Magic: 0x" << std::hex << pOptionalHeader->Magic << std::dec
            << " (" << (pOptionalHeader->Magic == 0x10b ? "PE32" : "PE32+") << ")" << std::endl;
        std::cout << "  Address of Entry Point: 0x" << std::hex << pOptionalHeader->AddressOfEntryPoint << std::dec << std::endl;
        std::cout << "  Image Base: 0x" << std::hex << pOptionalHeader->ImageBase << std::dec << std::endl;
        std::cout << "  Section Alignment: 0x" << std::hex << pOptionalHeader->SectionAlignment << std::dec << std::endl;
        std::cout << "  File Alignment: 0x" << std::hex << pOptionalHeader->FileAlignment << std::dec << std::endl;
        std::cout << "  Size of Image: 0x" << std::hex << pOptionalHeader->SizeOfImage << std::dec << std::endl;
        std::cout << "  Size of Headers: 0x" << std::hex << pOptionalHeader->SizeOfHeaders << std::dec << std::endl;
        std::cout << "  Subsystem: " << pOptionalHeader->Subsystem<< std::endl;
        std::cout << "  DLL Characteristics: 0x" << std::hex << pOptionalHeader->DllCharacteristics << std::dec << std::endl;
        std::cout << "  Number of RVA and Sizes: " << pOptionalHeader->NumberOfRvaAndSizes << std::endl;
        // Print Data Directories
        std::cout << "Data Directories:" << std::endl;
        const char* directoryNames[] = {
            "Export Table", "Import Table", "Resource Table", "Exception Table",
            "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
            "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
        };
        for (uint32_t i = 0; i < pOptionalHeader->NumberOfRvaAndSizes && i < 16; i++)
        {
            const auto& dir = pOptionalHeader->DataDirectory[i];
            if (dir.VirtualAddress != 0 || dir.Size != 0) {
                std::cout << "  " << directoryNames[i] << ": RVA=0x" << std::hex << dir.VirtualAddress
                    << ", Size=0x" << dir.Size << std::dec << std::endl;
            }
        }

    }
    else if (m_FileType == FILE_TYPE_X86_PE)
    {
       
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
        std::cout << "Optional Header:" << std::endl;
        std::cout << "  Magic: 0x" << std::hex << pOptionalHeader->Magic << std::dec
            << " (" << (pOptionalHeader->Magic == 0x10b ? "PE32" : "PE32+") << ")" << std::endl;
        std::cout << "  Address of Entry Point: 0x" << std::hex << pOptionalHeader->AddressOfEntryPoint << std::dec << std::endl;
        std::cout << "  Image Base: 0x" << std::hex << pOptionalHeader->ImageBase << std::dec << std::endl;
        std::cout << "  Section Alignment: 0x" << std::hex << pOptionalHeader->SectionAlignment << std::dec << std::endl;
        std::cout << "  File Alignment: 0x" << std::hex << pOptionalHeader->FileAlignment << std::dec << std::endl;
        std::cout << "  Size of Image: 0x" << std::hex << pOptionalHeader->SizeOfImage << std::dec << std::endl;
        std::cout << "  Size of Headers: 0x" << std::hex << pOptionalHeader->SizeOfHeaders << std::dec << std::endl;
        std::cout << "  Subsystem: " << pOptionalHeader->Subsystem << std::endl;
        std::cout << "  DLL Characteristics: 0x" << std::hex << pOptionalHeader->DllCharacteristics << std::dec << std::endl;
        std::cout << "  Number of RVA and Sizes: " << pOptionalHeader->NumberOfRvaAndSizes << std::endl;
        // Print Data Directories
        std::cout << "Data Directories:" << std::endl;
        const char* directoryNames[] = {
            "Export Table", "Import Table", "Resource Table", "Exception Table",
            "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
            "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
        };
        for (uint32_t i = 0; i < pOptionalHeader->NumberOfRvaAndSizes && i < 16; i++)
        {
            const auto& dir = pOptionalHeader->DataDirectory[i];
            if (dir.VirtualAddress != 0 || dir.Size != 0) {
                std::cout << "  " << directoryNames[i] << ": RVA=0x" << std::hex << dir.VirtualAddress
                    << ", Size=0x" << dir.Size << std::dec << std::endl;
            }
        }

    }

    return;
}

void ParseBase::ParseDataDirectoryTable()
{
    ParseExportTable();
    ParseImportTable();
    ParseRscTable();
    ParseTlsTable();
    ParseRelocTable();

    return;
}

void ParseBase::ParseExportTable()
{
    //导出表在数据目录表的第一项索引为0
    uint32_t ExportTableRVA = 0;
    uint32_t ExportTableSize = 0;
    //获取导入表 rva 和 size
    if (m_FileType == FILE_TYPE_X64_PE)
    {
        //x64
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
        ExportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportTableSize = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else
    {
        //x86
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
        ExportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportTableSize = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // If there's no import directory, return
    if (ExportTableRVA == 0 || ExportTableSize == 0)
    {
        printf("不存在导出表\n");
        return;
    }

    //获取到导出表的指针
    // 将Rva转成Foa
    uint32_t exportDirOffset = Utils::RvaToFoa(m_pFileBuff, ExportTableRVA);
    if (exportDirOffset == 0)
    {
        std::cerr << "Failed to convert export directory RVA to offset" << std::endl;
        return;
    }

    //解析导出表
    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)m_pFileBuff + exportDirOffset);

    // 获取导出表各项数据
    DWORD numberOfFunctions = pExportDir->NumberOfFunctions;
    DWORD numberOfNames = pExportDir->NumberOfNames;
    DWORD base = pExportDir->Base;

    // 转换地址表RVA到FOA
    uint32_t eatOffset = Utils::RvaToFoa(m_pFileBuff, pExportDir->AddressOfFunctions);
    DWORD* pFunctions = (DWORD*)((uint8_t*)m_pFileBuff + eatOffset);

    // 转换名称指针表RVA到FOA
    uint32_t enptOffset = Utils::RvaToFoa(m_pFileBuff, pExportDir->AddressOfNames);
    DWORD* pNames = (DWORD*)((uint8_t*)m_pFileBuff + enptOffset);

    // 转换序号表RVA到FOA
    uint32_t eotOffset = Utils::RvaToFoa(m_pFileBuff, pExportDir->AddressOfNameOrdinals);
    WORD* pOrdinals = (WORD*)((uint8_t*)m_pFileBuff + eotOffset);

    // 打印导出表基本信息
    printf("\n========== Export Table ==========\n");
    printf("Characteristics: 0x%08X\n", pExportDir->Characteristics);
    printf("TimeDateStamp: 0x%08X\n", pExportDir->TimeDateStamp);
    printf("MajorVersion: %d\n", pExportDir->MajorVersion);
    printf("MinorVersion: %d\n", pExportDir->MinorVersion);
    printf("Name RVA: 0x%08X\n", pExportDir->Name);
    printf("Base: %d\n", base);
    printf("NumberOfFunctions: %d\n", numberOfFunctions);
    printf("NumberOfNames: %d\n", numberOfNames);

    // 获取并打印DLL名称
    uint32_t nameOffset = Utils::RvaToFoa(m_pFileBuff, pExportDir->Name);
    if (nameOffset != 0)
    {
        printf("DLL Name: %s\n", (char*)((uint8_t*)m_pFileBuff + nameOffset));
    }

    // 打印导出函数信息
    printf("\nExported Functions:\n");
    printf("Ordinal  RVA      Name (if available)\n");
    printf("------------------------------------\n");

    for (DWORD i = 0; i < numberOfFunctions; i++)
    {
        DWORD functionRva = pFunctions[i];
        if (functionRva == 0)
            continue; // 跳过空项

        // 检查是否为转发导出
        if (functionRva >= ExportTableRVA && functionRva < ExportTableRVA + ExportTableSize)
        {
            uint32_t forwardOffset = Utils::RvaToFoa(m_pFileBuff, functionRva);
            printf("%-8d 0x%08X (forwarded to %s)\n",
                base + i, functionRva, (char*)((uint8_t*)m_pFileBuff + forwardOffset));
        }
        else
        {
            // 查找是否有名称
            bool hasName = false;
            const char* funcName = nullptr;
            WORD ordinal = 0;

            for (DWORD j = 0; j < numberOfNames; j++)
            {
                if (pOrdinals[j] == i)
                {
                    uint32_t nameRva = pNames[j];
                    uint32_t nameOffset = Utils::RvaToFoa(m_pFileBuff, nameRva);
                    funcName = (const char*)((uint8_t*)m_pFileBuff + nameOffset);
                    ordinal = base + i;
                    hasName = true;
                    break;
                }
            }

            if (hasName)
            {
                printf("%-8d 0x%08X %s\n", ordinal, functionRva, funcName);
            }
            else
            {
                printf("%-8d 0x%08X\n", base + i, functionRva);
            }
        }
    }

    return;

}

void ParseBase::ParseImportTable()
{
    uint32_t importDirRVA = 0;
    uint32_t importDirSize = 0;
    // 获取导入表 rva 和 size
    if (m_FileType == FILE_TYPE_X64_PE)
    {
        // x64
        IMAGE_OPTIONAL_HEADER64* pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
        importDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirSize = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    else
    {
        // x86
        IMAGE_OPTIONAL_HEADER32* pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
        importDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirSize = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    // If there's no import directory, return
    if (importDirRVA == 0 || importDirSize == 0)
    {
        printf("不存在导入表\n");
        return;
    }
    
    // 将Rva转成Foa
    uint32_t importDirOffset = Utils::RvaToFoa(m_pFileBuff, importDirRVA);
    if (importDirOffset == 0)
    {
        std::cerr << "Failed to convert import directory RVA to offset" << std::endl;
        return;
    }

    // 获取导入表目录指针
    IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)m_pFileBuff + importDirOffset);

    printf("\n========== Import Table ==========\n");

    // 遍历所有导入的DLL
    while (pImportDesc->OriginalFirstThunk != 0 || pImportDesc->FirstThunk != 0)
    {
        // 获取DLL名称
        uint32_t dllNameOffset = Utils::RvaToFoa(m_pFileBuff, pImportDesc->Name);
        if (dllNameOffset == 0)
        {
            std::cerr << "Invalid DLL name RVA" << std::endl;
            pImportDesc++;
            continue;
        }
        const char* dllName = (const char*)((uint8_t*)m_pFileBuff + dllNameOffset);
        printf("\nDLL: %s\n", dllName);

        // 决定使用OriginalFirstThunk还是FirstThunk（通常两者相同）
        uint32_t thunkRVA = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
        uint32_t thunkOffset = Utils::RvaToFoa(m_pFileBuff, thunkRVA);
        if (thunkOffset == 0)
        {
            std::cerr << "Invalid thunk RVA" << std::endl;
            pImportDesc++;
            continue;
        }

        printf("  Ordinal/Hint  Name\n");
        printf("  ----------------------------\n");

        // 区分32位和64位的导入表项
        if (m_FileType == FILE_TYPE_X64_PE)
        {
            // 64位处理
            IMAGE_THUNK_DATA64* pThunk64 = (IMAGE_THUNK_DATA64*)((uint8_t*)m_pFileBuff + thunkOffset);
            while (pThunk64->u1.AddressOfData != 0)
            {
                if (pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    // 按序号导入
                    uint32_t ordinal = static_cast<uint32_t>(pThunk64->u1.Ordinal & 0xFFFF);
                    printf("  %08X       (Ordinal)\n", ordinal);
                }
                else
                {
                    // 按名称导入
                    uint32_t nameRVA = static_cast<uint32_t>(pThunk64->u1.AddressOfData);
                    uint32_t nameOffset = Utils::RvaToFoa(m_pFileBuff, nameRVA);
                    if (nameOffset != 0)
                    {
                        IMAGE_IMPORT_BY_NAME* pImportName = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)m_pFileBuff + nameOffset);
                        printf("  %04X         %s\n", pImportName->Hint, pImportName->Name);
                    }
                }

                // 显示IAT信息（如果可用）
                if (pImportDesc->FirstThunk != 0)
                {
                    uint32_t iatOffset = Utils::RvaToFoa(m_pFileBuff, pImportDesc->FirstThunk +
                        (uint32_t)((uint8_t*)pThunk64 - (uint8_t*)((uint8_t*)m_pFileBuff + thunkOffset)));
                    if (iatOffset != 0)
                    {
                        IMAGE_THUNK_DATA64* pIatEntry = (IMAGE_THUNK_DATA64*)((uint8_t*)m_pFileBuff + iatOffset);
                        printf("    [IAT] RVA: 0x%016llX\n", pIatEntry->u1.AddressOfData);
                    }
                }

                pThunk64++;
            }
        }
        else
        {
            // 32位处理
            IMAGE_THUNK_DATA32* pThunk32 = (IMAGE_THUNK_DATA32*)((uint8_t*)m_pFileBuff + thunkOffset);
            while (pThunk32->u1.AddressOfData != 0)
            {
                if (pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                {
                    // 按序号导入
                    uint32_t ordinal = pThunk32->u1.Ordinal & 0xFFFF;
                    printf("  %08X       (Ordinal)\n", ordinal);
                }
                else
                {
                    // 按名称导入
                    uint32_t nameRVA = pThunk32->u1.AddressOfData;
                    uint32_t nameOffset = Utils::RvaToFoa(m_pFileBuff, nameRVA);
                    if (nameOffset != 0)
                    {
                        IMAGE_IMPORT_BY_NAME* pImportName = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)m_pFileBuff + nameOffset);
                        printf("  %04X         %s\n", pImportName->Hint, pImportName->Name);
                    }
                }

                // 显示IAT信息（如果可用）
                if (pImportDesc->FirstThunk != 0)
                {
                    uint32_t iatOffset = Utils::RvaToFoa(m_pFileBuff, pImportDesc->FirstThunk +
                        (uint32_t)((uint8_t*)pThunk32 - (uint8_t*)((uint8_t*)m_pFileBuff + thunkOffset)));
                    if (iatOffset != 0)
                    {
                        IMAGE_THUNK_DATA32* pIatEntry = (IMAGE_THUNK_DATA32*)((uint8_t*)m_pFileBuff + iatOffset);
                        printf("    [IAT] RVA: 0x%08X\n", pIatEntry->u1.AddressOfData);
                    }
                }

                pThunk32++;
            }
        }

        pImportDesc++;
    }


    return;
}




void ParseBase::ParseRscTable()
{
    //解析资源表
    return;
}

void ParseBase::ParseRelocTable()
{
    uint32_t relocRVA = 0;
    uint32_t relocSize = 0;

    if (m_FileType == FILE_TYPE_X64_PE) {
        IMAGE_OPTIONAL_HEADER64* pOptHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
        relocRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    else {
        IMAGE_OPTIONAL_HEADER32* pOptHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
        relocRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }

    if (relocRVA == 0 || relocSize == 0) {
        printf("无重定位表\n");
        return;
    }

    uint32_t relocOffset = Utils::RvaToFoa(m_pFileBuff, relocRVA);
    if (relocOffset == 0) {
        std::cerr << "重定位表RVA转换失败" << std::endl;
        return;
    }

    printf("\n========== Relocation Table ==========\n");

    IMAGE_BASE_RELOCATION* pRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)m_pFileBuff + relocOffset);
    DWORD totalSize = 0;

    while (totalSize < relocSize && pRelocBlock->SizeOfBlock > 0) {
        printf("Page RVA: 0x%08X, Block Size: %d\n",
            pRelocBlock->VirtualAddress, pRelocBlock->SizeOfBlock);

        DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pEntries = (WORD*)(pRelocBlock + 1);

        for (DWORD i = 0; i < entryCount; i++) {
            WORD entry = pEntries[i];
            if (entry == 0) continue;

            BYTE type = entry >> 12;
            WORD offset = entry & 0xFFF;

            const char* typeStr = "UNKNOWN";
            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE: typeStr = "ABS"; break;
            case IMAGE_REL_BASED_HIGHLOW: typeStr = "HIGHLOW"; break;
            case IMAGE_REL_BASED_DIR64: typeStr = "DIR64"; break;
            case IMAGE_REL_BASED_HIGH: typeStr = "HIGH"; break;
            case IMAGE_REL_BASED_LOW: typeStr = "LOW"; break;
            }

            printf("  [%04d] Offset: 0x%04X, Type: %s\n",
                i, offset, typeStr);
        }

        totalSize += pRelocBlock->SizeOfBlock;
        pRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pRelocBlock + pRelocBlock->SizeOfBlock);
    }
}

void ParseBase::ParseTlsTable()
{
    uint32_t tlsRVA = 0;
    uint32_t tlsSize = 0;

    if (m_FileType == FILE_TYPE_X64_PE) {
        IMAGE_OPTIONAL_HEADER64* pOptHeader = (IMAGE_OPTIONAL_HEADER64*)m_pOptionalHeader;
        tlsRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        tlsSize = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    }
    else {
        IMAGE_OPTIONAL_HEADER32* pOptHeader = (IMAGE_OPTIONAL_HEADER32*)m_pOptionalHeader;
        tlsRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        tlsSize = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    }

    if (tlsRVA == 0 || tlsSize == 0) {
        printf("无TLS表\n");
        return;
    }

    uint32_t tlsOffset = Utils::RvaToFoa(m_pFileBuff, tlsRVA);
    if (tlsOffset == 0) {
        std::cerr << "TLS表RVA转换失败" << std::endl;
        return;
    }

    printf("\n========== TLS Table ==========\n");

    if (m_FileType == FILE_TYPE_X64_PE) {
        IMAGE_TLS_DIRECTORY64* pTls = (IMAGE_TLS_DIRECTORY64*)((uint8_t*)m_pFileBuff + tlsOffset);
        printf("StartAddressOfRawData: 0x%016llX\n", pTls->StartAddressOfRawData);
        printf("EndAddressOfRawData:   0x%016llX\n", pTls->EndAddressOfRawData);
        printf("AddressOfIndex:        0x%016llX\n", pTls->AddressOfIndex);
        printf("AddressOfCallBacks:    0x%016llX\n", pTls->AddressOfCallBacks);
        printf("SizeOfZeroFill:        %u\n", pTls->SizeOfZeroFill);
        printf("Characteristics:       0x%08X\n", pTls->Characteristics);

        // 解析TLS回调函数
        if (pTls->AddressOfCallBacks != 0) {
            uint32_t cbOffset = Utils::RvaToFoa(m_pFileBuff, (uint32_t)pTls->AddressOfCallBacks);
            if (cbOffset != 0) {
                printf("\nTLS Callbacks:\n");
                ULONGLONG* pCallbacks = (ULONGLONG*)((uint8_t*)m_pFileBuff + cbOffset);
                for (int i = 0; pCallbacks[i] != 0; i++) {
                    printf("  [%d] RVA: 0x%016llX\n", i, pCallbacks[i]);
                }
            }
        }
    }
    else {
        IMAGE_TLS_DIRECTORY32* pTls = (IMAGE_TLS_DIRECTORY32*)((uint8_t*)m_pFileBuff + tlsOffset);
        printf("StartAddressOfRawData: 0x%08X\n", pTls->StartAddressOfRawData);
        printf("EndAddressOfRawData:   0x%08X\n", pTls->EndAddressOfRawData);
        printf("AddressOfIndex:        0x%08X\n", pTls->AddressOfIndex);
        printf("AddressOfCallBacks:    0x%08X\n", pTls->AddressOfCallBacks);
        printf("SizeOfZeroFill:        %u\n", pTls->SizeOfZeroFill);
        printf("Characteristics:       0x%08X\n", pTls->Characteristics);

        // 解析TLS回调函数
        if (pTls->AddressOfCallBacks != 0) {
            uint32_t cbOffset = Utils::RvaToFoa(m_pFileBuff, pTls->AddressOfCallBacks);
            if (cbOffset != 0) {
                printf("\nTLS Callbacks:\n");
                DWORD* pCallbacks = (DWORD*)((uint8_t*)m_pFileBuff + cbOffset);
                for (int i = 0; pCallbacks[i] != 0; i++) {
                    printf("  [%d] RVA: 0x%08X\n", i, pCallbacks[i]);
                }
            }
        }
    }
}

void ParseBase::ParseSectionHeaders()
{

    std::cout << "Section Information:" << std::endl;
    std::cout << "-------------------" << std::endl;
    std::cout << std::left << std::setw(10) << "Name"
        << std::right << std::setw(12) << "VirtSize"
        << std::setw(12) << "VirtAddr"
        << std::setw(12) << "RawSize"
        << std::setw(12) << "RawAddr"
        << std::setw(12) << "Chars"
        << std::endl;
    size_t SectionNum = m_pFileHeader->NumberOfSections;

    for (size_t i = 0; i < SectionNum; i++)
    {
        std::string name(reinterpret_cast<const char*>(m_pSectionHeaders[i].Name),
            strnlen(reinterpret_cast<const char*>(m_pSectionHeaders[i].Name), 8));
        std::cout << std::left << std::setw(10) << name
            << std::right << std::hex
            << "0x" << std::setw(8) << m_pSectionHeaders[i].Misc.VirtualSize
            << "  0x" << std::setw(8) << m_pSectionHeaders[i].VirtualAddress
            << "  0x" << std::setw(8) << m_pSectionHeaders[i].SizeOfRawData
            << "  0x" << std::setw(8) << m_pSectionHeaders[i].PointerToRawData
            << "  0x" << std::setw(8) << m_pSectionHeaders[i].Characteristics
            << std::dec << std::endl;
    }

    return;
}























