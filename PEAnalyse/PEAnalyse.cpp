

#include"../Source/Implement/ParseBase.h"


int main()
{
    std::cout << "Hello World!\n";

    
   // std::wstring Path = L"C:\\Users\\12764\\source\\project\\MyFileMon\\Bin\\x64\\debug\\MyFileMon.dll";
    std::wstring Path = L"C:\\Users\\12764\\source\\project\\MyFileMon\\Bin\\x86\\debug\\MyFileMon.dll";
   
  
    ParseBase test;
    test.InitFileInfo(Path);
    test.DatCollection();
    test.DataParse();
 

    return 0;
}


