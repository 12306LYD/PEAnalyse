

#include"../Source/Implement/ParseBase.h"


int main()
{
    std::cout << "Hello World!\n";

    std::wstring Path = L"C:\\Users\\12764\\Desktop\\34\\MyTest.exe";
  
    ParseBase test;
    test.InitFileInfo(Path);
    test.DatCollection();
    test.DataParse();
 

    return 0;
}


