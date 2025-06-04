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
	//解析Dos头
	void ParseDosHeader();
	//解析Nt头(包括文件头、拓展头)
	void ParseNtHeader();
	
	//解析数据目录表(具体解析导入表 导出表 资源表 重定位表等)
	void ParseDataDirectoryTable();

	void ParseExportTable();
	void ParseImportTable();
	void ParseRscTable();
	void ParseRelocTable();
	void ParseTlsTable();
	
	//解析区段表
	void ParseSectionHeaders();

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
	//保存指向文件头的指针
	IMAGE_FILE_HEADER* m_pFileHeader;
	//保存指向拓展头的指针(受目标文件32位还是64位影响 使用Lpvoid代替)
	LPVOID m_pOptionalHeader;
	//保存指向SectionHeader首地址的指针
	IMAGE_SECTION_HEADER* m_pSectionHeaders;

	//保存数据目录表的个数
	DWORD m_DataDirectoryNum;
	//保存指向数据目录表的指针
	IMAGE_DATA_DIRECTORY* m_pDataDirectory;

};











#endif



