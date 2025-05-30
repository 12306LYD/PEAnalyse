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
	//获取DOS Header
	LPVOID GetPeDosHeader(LPVOID FileBuff);
	//获取 NT header
	LPVOID GetPeNtheader(LPVOID FileBuff);

	//获取Sectionheader
	LPVOID GetPeSectionHeader(LPVOID FileBase);



}








#endif
