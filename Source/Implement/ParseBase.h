#ifndef _PARSE_BASE_HEADER_
#define _PARSE_BASE_HEADER_


#include"../Utils/Utils.h"

class ParseBase
{
public:
	ParseBase();
	virtual ~ParseBase();
public:
	//初始化文件信息
	bool InitFileInfo(std::wstring FilePath);
	//解析
	void Parse();

public:


public:
	//保存文件路径信息
	std::wstring m_FilePath;
	//保存文件类型
	int m_FileType;
	//保存文件大小(字节为单位)
	DWORD64 m_FileSize;
	//保存读取文件内容的起始地址
	LPVOID m_pFileBuff;

};











#endif



