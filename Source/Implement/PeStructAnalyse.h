#ifndef _PARSE_STRUCT_ANALYSE_HEADER_
#define _PARSE_STRUCT_ANALYSE_HEADER_


/*

// Dos头
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number（重要）
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // 指向nt头的偏移，(重要)
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;



  //nt 头(x86和x64不同 这里以64位距离)
  typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;                          //固定值值 4550 用来判断是否是Pe类型文件
    IMAGE_FILE_HEADER FileHeader;             //结构体 包含文件头的相关数据
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;   //结构体 包含拓展头的相关数据
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;                          //固定值值 4550 用来判断是否是Pe类型文件
    IMAGE_FILE_HEADER FileHeader;             //结构体 包含文件头的相关数据
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;   //结构体 包含拓展头的相关数据
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;



//文件头相关数据含义
typedef struct _IMAGE_FILE_HEADER {
        WORD    Machine;              '// 每个CPU拥有唯一的Machine码 -> 4C 01 -> PE -> 兼容32位Intel X86芯片'

        WORD    NumberOfSections;     '// 指文件中存在的节段（又称节区）数量，也就是节表中的项数 -> 00 04 -> 4
                                       // 该值一定要大于0，且当定义的节段数与实际不符时，将发生运行错误。'(重要)

        DWORD   TimeDateStamp;         // PE文件的创建时间，一般有连接器填写 -> 38 D1 29 1E
        DWORD   PointerToSymbolTable;  // COFF文件符号表在文件中的偏移 -> 00 00 00 00
        DWORD   NumberOfSymbols;       // 符号表的数量 -> 00 00 00 00

        WORD    SizeOfOptionalHeader; '// 指出IMAGE_OPTIONAL_HEADER32结构体的长度。->  00 E0 -> 224字节
                                       // PE32+格式文件中使用的是IMAGE_OPTIONAL_HEADER64结构体，
                                       // 这两个结构体尺寸是不相同的，所以需要在SizeOfOptionalHeader中指明大小。'

        WORD    Characteristics;      '// 标识文件的属性，二进制中每一位代表不同属性 -> 0F 01
                                       // 属性参见https://blog.csdn.net/qiming_zhang/article/details/7309909#3.2.2'
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


//拓展头
typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD    Magic;                     '// 魔数 32位为0x10B，64位为0x20B，ROM镜像为0x107'
        BYTE    MajorLinkerVersion;         // 链接器的主版本号 -> 05
        BYTE    MinorLinkerVersion;         // 链接器的次版本号 -> 0C
        DWORD   SizeOfCode;                 // 代码节大小，一般放在“.text”节里，必须是FileAlignment的整数倍 -> 40 00 04 00
        DWORD   SizeOfInitializedData;      // 已初始化数大小，一般放在“.data”节里，必须是FileAlignment的整数倍 -> 40 00 0A 00
        DWORD   SizeOfUninitializedData;    // 未初始化数大小，一般放在“.bss”节里，必须是FileAlignment的整数倍 -> 00 00 00 00
        DWORD   AddressOfEntryPoint;       '// 指出程序最先执行的代码起始地址(RVA) -> 00 00 10 00'
        DWORD   BaseOfCode;                 // 代码基址，当镜像被加载进内存时代码节的开头RVA。必须是SectionAlignment的整数倍 -> 40 00 10 00

        DWORD   BaseOfData;                 // 数据基址，当镜像被加载进内存时数据节的开头RVA。必须是SectionAlignment的整数倍 -> 40 00 20 00
                                            // 在64位文件中此处被并入紧随其后的ImageBase中。

        DWORD   ImageBase;                 '// 当加载进内存时，镜像的第1个字节的首选地址。
                                            // WindowEXE默认ImageBase值为00400000，DLL文件的ImageBase值为10000000，也可以指定其他值。
                                            // 执行PE文件时，PE装载器先创建进程，再将文件载入内存，
                                            // 然后把EIP寄存器的值设置为ImageBase+AddressOfEntryPoint'

                                           '// PE文件的Body部分被划分成若干节段，这些节段储存着不同类别的数据。'
        DWORD   SectionAlignment;          '// SectionAlignment指定了节段在内存中的最小单位， -> 00 00 10 00'
        DWORD   FileAlignment;             '// FileAlignment指定了节段在磁盘文件中的最小单位，-> 00 00 02 00
                                            // SectionAlignment必须大于或者等于FileAlignment'

        WORD    MajorOperatingSystemVersion;// 主系统的主版本号 -> 00 04
        WORD    MinorOperatingSystemVersion;// 主系统的次版本号 -> 00 00
        WORD    MajorImageVersion;          // 镜像的主版本号 -> 00 00
        WORD    MinorImageVersion;          // 镜像的次版本号 -> 00 00
        WORD    MajorSubsystemVersion;      // 子系统的主版本号 -> 00 04
        WORD    MinorSubsystemVersion;      // 子系统的次版本号 -> 00 00
        DWORD   Win32VersionValue;          // 保留，必须为0 -> 00 00 00 00

        DWORD   SizeOfImage;               '// 当镜像被加载进内存时的大小，包括所有的文件头。向上舍入为SectionAlignment的倍数。
                                            // 一般文件大小与加载到内存中的大小是不同的。 -> 00 00 50 00'

        DWORD   SizeOfHeaders;             '// 所有头(包括节表)的总大小，向上舍入为FileAlignment的倍数。
                                            // 可以以此值作为PE文件第一节的文件偏移量。-> 00 00 04 00'

        DWORD   CheckSum;                   // 镜像文件的校验和 -> 00 00 B4 99

        WORD    Subsystem;                 '// 运行此镜像所需的子系统 -> 00 02 -> 窗口应用程序
                                            // 用来区分系统驱动文件（*.sys)与普通可执行文件（*.exe，*.dll），
                                            // 参考：https://blog.csdn.net/qiming_zhang/article/details/7309909#3.2.3'

        WORD    DllCharacteristics;         // DLL标识 -> 00 00
        DWORD   SizeOfStackReserve;         // 最大栈大小。CPU的堆栈。默认是1MB。-> 00 10 00 00
        DWORD   SizeOfStackCommit;          // 初始提交的堆栈大小。默认是4KB -> 00 00 10 00
        DWORD   SizeOfHeapReserve;          // 最大堆大小。编译器分配的。默认是1MB ->00 10 00 00
        DWORD   SizeOfHeapCommit;           // 初始提交的局部堆空间大小。默认是4K ->00 00 10 00
        DWORD   LoaderFlags;                // 保留，必须为0 -> 00 00 00 00

        DWORD   NumberOfRvaAndSizes;       '// 指定DataDirectory的数组个数，由于以前发行的Windows NT的原因，它只能为16。 -> 00 00 00 10'
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; '// 数据目录数组。每个成员都是IMAGE_DATA_DIRECTORY结构。'
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;


    //数据目录表中的结构体
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress; 表示指向对应表的rva
    DWORD   Size;           表示指向对应表的大小
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;




sectionheaders 是一个结构体数组，个数由文件头中的NumberOfSections 确定
每一个成员都是IMAGE_SECTION_HEADER 类型的结构体，字段含义如下

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];    对应section的名称，字符数组大小是8字节。
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;                   节的 RVA 地址
    DWORD   SizeOfRawData;                    在文件中对齐后的尺寸
    DWORD   PointerToRawData;                 在文件中的偏移量    对于可执行镜像文件，这个字段必须是IMAGE_OPTIONAL_HEADER.FileAlignment的倍数。
    DWORD   PointerToRelocations;            在OBJ文件中使用，重定位的偏移
    DWORD   PointerToLinenumbers;             行号表的偏移（供调试使用地）
    WORD    NumberOfRelocations;             在OBJ文件中使用，重定位项数目
    WORD    NumberOfLinenumbers;             行号表中行号的数目
    DWORD   Characteristics;                 节属性如可读，可写，可执行等
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


Name：区块名。这是一个由8位的ASCII 码名，用来定义区块的名称。多数区块名都习惯性以一个“.”作为开头（例如：.text），这个“.” 实际上是不是必须的。值得我们注意的是，如果区块名超过 8 个字节，则没有最后的终止标志“NULL” 字节。并且前边带有一个“的区块名字会从连接器那里得到特殊的待遇，前边带有
” 的相同名字的区块在载入时候将会被合并，在合并之后的区块中，他们是按照“$” 后边的字符的字母顺序进行合并的。
另外小甲鱼童鞋要跟大家啰嗦一下的是：每个区块的名称都是唯一的，不能有同名的两个区块。但事实上节的名称不代表任何含义，他的存在仅仅是为了正规统一编程的时候方便程序员查看方便而设置的一个标记而已。所以将包含代码的区块命名为“.Data” 或者说将包含数据的区块命名为“.Code” 都是合法的。
因此，小甲鱼建议大家：当我们要从PE 文件中读取需要的区块时候，不能以区块的名称作为定位的标准和依据，正确的方法是按照 IMAGE_OPTIONAL_HEADER32 结构中的数据目录字段结合进行定位。

Virtual Size（VSize）：对表对应的区块的大小，这是区块的数据在没有进行对齐处理前的实际大小。
Virtual Address（VOffset）：该区块装载到内存中的RVA 地址。这个地址是按照内存页来对齐的，因此它的数值总是 SectionAlignment 的值的整数倍。在Microsoft 工具中，第一个块的默认 RVA 总为1000h。在OBJ 中，该字段没有意义地，并被设为0。
SizeOfRawData（RSize）：该区块在磁盘中所占的大小。在可执行文件中，该字段是已经被FileAlignment 潜规则处理过的长度。
PointerToRawData（ROffset）：该区块在磁盘中的偏移。这个数值是从文件头开始算起的偏移量哦。


PointerToRelocations：这哥们在EXE文件中没有意义，在OBJ 文件中，表示本区块重定位信息的偏移值。（在OBJ 文件中如果不是零，它会指向一个IMAGE_RELOCATION 结构的数组）
PointerToLinenumbers：行号表在文件中的偏移值，文件的调试信息，于我们没用，鸡肋。
NumberOfRelocations：这哥们在EXE文件中也没有意义，在OBJ 文件中，是本区块在重定位表中的重定位数目来着。
NumberOfLinenumbers：该区块在行号表中的行号数目，鸡肋。
Characteristics：该区块的属性。该字段是按位来指出区块的属性（如代码/数据/可读/可写等）的标志。

PointerToRelocations：这哥们在EXE文件中没有意义，在OBJ 文件中，表示本区块重定位信息的偏移值。（在OBJ 文件中如果不是零，它会指向一个IMAGE_RELOCATION 结构的数组）
PointerToLinenumbers：行号表在文件中的偏移值，文件的调试信息，于我们没用，鸡肋。
NumberOfRelocations：这哥们在EXE文件中也没有意义，在OBJ 文件中，是本区块在重定位表中的重定位数目来着。
NumberOfLinenumbers：该区块在行号表中的行号数目，鸡肋。
Characteristics：该区块的属性。该字段是按位来指出区块的属性（如代码/数据/可读/可写等）的标志。






*/
















#endif
