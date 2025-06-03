

#include"../Source/Implement/ParseBase.h"


int main()
{
    std::cout << "Hello World!\n";


    std::wstring Path = L"C:\\Users\\12764\\source\\project\\MyFileMon\\Bin\\x64\\debug\\MyFileMon.dll";

    HMODULE base =  LoadLibraryW(Path.c_str());

    ParseBase test;
    //test.InitFileInfo(Path);

 

    return 0;
}


