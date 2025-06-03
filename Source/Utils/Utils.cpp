
#include"Utils.h"

std::string Utils::Unicode2Utf8(std::wstring unicode)
{
	std::string str_path;
	do
	{
		if (unicode.empty())
		{
			break;
		}
		int len = 0;
		len = WideCharToMultiByte(CP_UTF8, 0, unicode.c_str(), -1, NULL, 0, NULL, NULL);
		char* sz_utf8 = new char[len + 1] {};
		WideCharToMultiByte(CP_UTF8, 0, unicode.c_str(), -1, sz_utf8, len, NULL, NULL);
		str_path = sz_utf8;
		delete[]sz_utf8;
		sz_utf8 = nullptr;
	} while (FALSE);
	return str_path;
}

std::wstring Utils::UTF82WCS(std::string str_utf8)
{
	//预转换，得到所需空间的大小;
	int wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, str_utf8.c_str(), (int)str_utf8.size(), NULL, 0);
	//分配空间要给'\0'留个空间，MultiByteToWideChar不会给'\0'空间
	wchar_t* wsz_string = new wchar_t[wcsLen + 1] {};
	//转换
	::MultiByteToWideChar(CP_UTF8, NULL, str_utf8.c_str(), (int)str_utf8.size(), wsz_string, wcsLen);
	//最后加上'\0'
	wsz_string[wcsLen] = '\0';
	std::wstring unicode_string(wsz_string);
	delete[] wsz_string;
	wsz_string = NULL;
	return unicode_string;
}

int Utils::FileInfoCheck(std::wstring FilePath)
{
    // 打开文件
    HANDLE hFile = CreateFileW(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"无法打开文件: " << FilePath << L" 错误代码: " << GetLastError() << std::endl;
        return FILE_OPEN_FAILED;
    }
    // 创建文件映射
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        std::wcerr << L"无法创建文件映射" << std::endl;
        CloseHandle(hFile);
        return FILE_OPEN_FAILED;
    }
    // 映射视图
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ,0,0,0);
    if (pBase == NULL) {
        std::wcerr << L"无法映射文件视图" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FILE_OPEN_FAILED;
    }

    // 检查DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcerr << L"无效的DOS签名" << std::endl;
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FILE_TYPE_NOT_PE;
    }

    // 获取NT头
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::wcerr << L"无效的PE签名" << std::endl;
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FILE_TYPE_NOT_PE;
    }

    // 判断是32位还是64位
    bool is64Bit = false;
    if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        is64Bit = true;
    }
    else if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        is64Bit = false;
    }
    else {
        std::wcerr << L"未知的机器类型" << std::endl;
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FILE_TYPE_NOT_PE;
    }

    // 清理资源
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);


    return is64Bit ? FILE_TYPE_X64_PE : FILE_TYPE_X86_PE;
}

LPVOID Utils::GetPeDosHeader(LPVOID FileBuff)
{
    if (FileBuff==NULL)
    {
        return NULL;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuff;
    return pDosHeader;
}

LPVOID Utils::GetPeNtheader(LPVOID FileBuff)
{
    if (FileBuff==NULL)
    {
        return NULL;
    }
    //获取DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetPeDosHeader(FileBuff);
    if (pDosHeader == NULL)
    {
        return NULL;
    }
    // 获取NT头
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)FileBuff + pDosHeader->e_lfanew);
   
    return pNtHeaders;

}

LPVOID Utils::GetPeSectionHeader(LPVOID FileBase)
{
    if (FileBase==NULL)
    {
        return NULL;
    }
    // 获取NT头
    //先使用 PIMAGE_NT_HEADERS 获取信息 此时32 和64 位没有区别（未涉及到拓展头信息）
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)GetPeNtheader(FileBase);
    if (pNtHeaders==NULL)
    {
        return NULL;
    }
   
    // 判断是32位还是64位
    bool is64Bit = false;
    if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        is64Bit = true;
    }
    else if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        is64Bit = false;
    }
    else
    {
        //位置的机器类型
        return NULL;
    }

    //获取拓展头数据大小 64和32位程序需要进行区分
    DWORD sizeOfOptionalHeader = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    if (is64Bit)
    {
        //64位程序
        //先获取拓展头数据大小
        sizeOfOptionalHeader = ((PIMAGE_NT_HEADERS64)pNtHeaders)->FileHeader.SizeOfOptionalHeader;
        //再计算节区头位置
        pSectionHeader = (PIMAGE_SECTION_HEADER)(
            (BYTE*)pNtHeaders +
            sizeof(IMAGE_NT_HEADERS64) -
            sizeof(IMAGE_OPTIONAL_HEADER64) +
            sizeOfOptionalHeader
            );
    }
    else
    {
        //32位程序
        //先获取拓展头数据大小
        sizeOfOptionalHeader = ((PIMAGE_NT_HEADERS32)pNtHeaders)->FileHeader.SizeOfOptionalHeader;
        // 计算节区头位置
        pSectionHeader = (PIMAGE_SECTION_HEADER)(
            (BYTE*)pNtHeaders +
            sizeof(IMAGE_NT_HEADERS32) -
            sizeof(IMAGE_OPTIONAL_HEADER32) +
            sizeOfOptionalHeader
            );
    }
    
    return pSectionHeader;
}




