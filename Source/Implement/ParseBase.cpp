
#include"ParseBase.h"

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
}

void ParseBase::DataParse()
{
}












