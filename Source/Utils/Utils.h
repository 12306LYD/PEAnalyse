#ifndef _UTILS_HEADER_
#define _UTILS_HEADER_

#include <windows.h>
#include <iostream>
#include<string>
#include<vector>

#define FILE_OPEN_FAILED  -1  //打开文件失败 文件类型未知
#define FILE_TYPE_NOT_PE   0   //非PE类型文件
#define FILE_TYPE_X86_PE   1   //x86 PE类型文件
#define FILE_TYPE_X64_PE   2   //x64 PE类型文件





namespace Utils{

	std::string Unicode2Utf8(std::wstring unicode);
	std::wstring UTF82WCS(std::string str_utf8);

	//校验是否是PE格式文件以及是32位还是64位
	// -1 打开文件失败 0 非PE格式文件
	//  1 X86 位程序  2 X64 
	int FileInfoCheck(std::wstring FilePath);

	//判断文件是64还是32
	int GetFileMachineType(LPVOID FileBuff);

	//获取DOS Header首地址
	LPVOID GetPeDosHeader(LPVOID FileBuff);

	//获取 NT header首地址
	//返回的指针是LPVOID  需要根据文件的位数 x86 还是X64 使用不同的结构体进行解析
	// IMAGE_NT_HEADERS32 x86
	// IMAGE_NT_HEADERS64 x64
	LPVOID GetPeNtheader(LPVOID FileBuff);
	//获取文件头首地址
	LPVOID GetPeFileHeader(LPVOID FileBuff);
	
	//获取拓展头首地址
	LPVOID GetPeOptionalHeader(LPVOID FileBuff);

	//获取节区头Sectionheader首地址
	LPVOID GetPeSectionHeader(LPVOID FileBase);

	DWORD RvaToFoa(LPVOID FileBase,DWORD Rva);
}








#endif
