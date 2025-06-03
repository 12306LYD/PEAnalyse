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

	//获取PE结构中的各种数据信息
	void DatCollection();

	//解析PE结构中的各种数据信息
	void DataParse();

private:


public:
	//保存文件路径信息
	std::wstring m_FilePath;
	//保存文件类型
	int m_FileType;
	//保存文件大小(字节为单位)
	DWORD64 m_FileSize;
	//保存读取文件内容的起始地址
	LPVOID m_pFileBuff;


private:
	//保存指向Dos头的指针
	IMAGE_DOS_HEADER* m_pDosHeader;
	//保存指向NT头的指针(受目标文件32位还是64位影响 使用Lpvoid代替)
	LPVOID m_pNtHeader;
	//保存指向SectionHeader首地址的指针
	IMAGE_SECTION_HEADER* m_pSectionHeaders;


};











#endif



