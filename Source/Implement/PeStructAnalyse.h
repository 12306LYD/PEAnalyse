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


数据目录表索引含义如下:
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor



数据目录表第一项索引包含导出表的相关信息
如：
IMAGE_DATA_DIRECTORY DataDirectory;
 DataDirectory[0].VirtualAddress   表示导出表的RVA
 DataDirectory[0].Size             表示导出表的Size

 导出表结构如下：
 typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;             Characteristics：现在没有用到，一般为0
    DWORD   TimeDateStamp;               TimeDateStamp：导出表生成的时间戳，由连接器生成
    WORD    MajorVersion;                MajorVersion，MinorVersion：看名字是版本，实际貌似没有用，都是0
    WORD    MinorVersion;                MajorVersion，MinorVersion：看名字是版本，实际貌似没有用，都是0
    DWORD   Name;                        模块的名字，不是直接表示模块名称 本质是一个Rva  需要通过该RVa 解析出模块名车给
    DWORD   Base;                        序号的基数，按序号导出函数的序号值从Base开始递增
    DWORD   NumberOfFunctions;           所有导出函数的数量
    DWORD   NumberOfNames;               按名字导出函数的数量
    DWORD   AddressOfFunctions;         一个RVA，指向一个DWORD数组。数组中的每一项是一个导出函数的RVA，该RVA指向的是函数地址，数组个数与NumberOfFunctions相同
    DWORD   AddressOfNames;             一个RVA，依然指向一个DWORD数组，数组中的每一项仍然是一个RVA，该Rva指向的是函数名称，数组个数与NumberOfNames相同
    DWORD   AddressOfNameOrdinals;      一个RVA，还是指向一个WORD数组，数组中的每一项与AddressOfNames中的每一项对应，表示该名字的函数在AddressOfFunctions中的序号
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;



数据目录表的第二项：IMAGE_DIRECTORY_ENTRY_IMPORT，即导入表。

在 IMAGE_DATA_DIRECTORY 中，有几项的名字都和导入表有关系，
其中包括：IMAGE_DIRECTORY_ENTRY_IMPORT，IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT，IMAGE_DIRECTORY_ENTRY_IAT 和 IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
这几个导入都是用来干什么的，他们之间又是什么关系呢？听我慢慢道来。

IMAGE_DIRECTORY_ENTRY_IMPORT 就是我们通常所知道的 导入表，在 PE 文件加载时，会根据这个表里的内容加载依赖的 DLL ( 模块 )，并填充所需函数的地址。

IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 叫做 绑定导入表，在第一种导入表导入地址的修正是在PE加载时完成，如果一个PE文件导入的DLL或者函数多那么加载起来就会略显的慢一些，所以出现了绑定导入，
在加载以前就修正了导入表，这样就会快一些。

IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 叫做 延迟导入表，一个PE文件也许提供了很多功能，也导入了很多其他DLL，但是并非每次加载都会用到它提供的所有功能，
也不一定会用到它需要导入的所有DLL，因此延迟导入就出现了，只有在一个PE文件真正用到需要的DLL，这个DLL才会被加载，甚至于只有真正使用某个导入函数，这个函数地址才会被修正。

IMAGE_DIRECTORY_ENTRY_IAT 是 导入地址表，前面的三个表其实是导入函数的描述，真正的函数地址是被填充在导入地址表中的。



数据目录表第二项索引包含导入表的相关信息
如：
IMAGE_DATA_DIRECTORY DataDirectory;
 DataDirectory[1].VirtualAddress   表示导入表的RVA
 DataDirectory[1].Size             表示导入表的Size

 数据目录表的第二项指向导入表。导入表是一个IMAGE_IMPORT_DESCRIPTOR 类型的数组，每个被Pe链接的dll都会对应一个数组，
 这个数组没有明确的个数，是通过以全为null的数组作为结束。IMAGE_IMPORT_DESCRIPTOR 结构如下:

 typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;                        一个联合体，如果是数组的最后一项 Characteristics 为 0，否则 OriginalFirstThunk 保存一个 RVA，
                                             指向一个 IMAGE_THUNK_DATA 的数组，这个数组中的每一项表示一个导入函数，该数组以全为0作为结束标志。

    DWORD   TimeDateStamp;                  映象绑定前，这个值是0，绑定后是导入模块的时间戳

    DWORD   ForwarderChain;                 转发链，如果没有转发器，这个值是 -1 

    DWORD   Name;                           一个 RVA，指向导入模块的名字，所以一个 IMAGE_IMPORT_DESCRIPTOR 描述一个导入的DLL

    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
                                            也是一个 RVA，也指向一个 IMAGE_THUNK_DATA 数组 ，这个数组中的每一项表示一个导入函数，该数组以全为0作为结束标志。
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;



既然 OriginalFirstThunk 与 FirstThunk 都指向一个 IMAGE_THUNK_DATA 数组，
而且这两个域的名字都长得很像，他俩有什么区别呢？为了解答这个问题，先来认识一下 IMAGE_THUNK_DATA 结构：

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

ForwarderString 是转发用的，暂时不用考虑，Function 表示函数地址，如果是按序号导入 Ordinal 就有用了，若是按名字导入AddressOfData 便指向名字信息。
可以看出这个结构体就是一个大的union，大家都知道union虽包含多个域但是在不同时刻代表不同的意义那到底应该是名字还是序号，该如何区分呢？
可以通过Ordinal判断，如果Ordinal的最高位是1，就是按序号导入的，这时候，低16位就是导入序号，
如果最高位是0，则AddressOfData是一个RVA，指向一个IMAGE_IMPORT_BY_NAME结构，用来保存名字信息，
由于Ordinal和AddressOfData实际上是同一个内存空间，所以AddressOfData其实只有低31位可以表示RVA
，但是一个PE文件不可能超过2G，所以最高位永远为0，这样设计很合理的利用了空间。
实际编写代码的时候微软提供两个宏定义处理序号导入：IMAGE_SNAP_BY_ORDINAL 判断是否按序号导入，IMAGE_ORDINAL 用来获取导入序号。

IMAGE_IMPORT_BY_NAME 结构如下：
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;



这时我们可以回头看看 OriginalFirstThunk 与 FirstThunk，OriginalFirstThunk 指向的 IMAGE_THUNK_DATA 数组包含导入信息，在这个数组中只有 Ordinal 和 AddressOfData 是有用的，
因此可以通过 OriginalFirstThunk 查找到函数的地址。FirstThunk则略有不同，在PE文件加载以前或者说在导入表未处理以前，他所指向的数组与 OriginalFirstThunk 中的数组虽不是同一个，
但是内容却是相同的，都包含了导入信息，而在加载之后，FirstThunk 中的 Function 开始生效，他指向实际的函数地址，因为FirstThunk 实际上指向 IAT 中的一个位置，
IAT 就充当了 IMAGE_THUNK_DATA 数组，加载完成后，这些 IAT 项就变成了实际的函数地址，即 Function 的意义。

总结：
导入表其实是一个 IMAGE_IMPORT_DESCRIPTOR 的数组，每个导入的 DLL 对应一个 IMAGE_IMPORT_DESCRIPTOR。
IMAGE_IMPORT_DESCRIPTOR 包含两个 IMAGE_THUNK_DATA 数组，数组中的每一项对应一个导入函数。
加载前 OriginalFirstThunk 与 FirstThunk 的数组都指向名字信息，加载后 FirstThunk 数组指向实际的函数地址。






*/
















#endif
