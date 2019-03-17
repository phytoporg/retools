//
// Facilitates DLL injection.
//

#pragma once
 
#include <string>
#include <windows.h>

namespace ReTools { namespace Utils
{
    class Injector
    {
    public:
        //
        // Throws if process can't be found.
        //
        Injector(const std::string processName);

        bool InjectDll(const std::string& dllPath);

    private:
        HANDLE m_processHandle;
    };
}}

