
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



    return;
}

void ParseBase::ParseExportTable()
{
    return;
}

void ParseBase::ParseImportTable()
{
    return;
}

void ParseBase::ParseRscTable()
{
    return;
}

void ParseBase::ParseRelocRable()
{
    return;
}

void ParseBase::ParseTlsTable()
{
    return;
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























