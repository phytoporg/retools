#include "sigscanner.h"
#include <windows.h>
#include <Psapi.h>

#include <iostream>

namespace ReTools { namespace Utils {
    SigScanner::SigScanner(const std::string& moduleName)
    {
         const HMODULE ModuleHandle = GetModuleHandleA(moduleName.c_str());
         if (ModuleHandle == nullptr)
         {
             throw std::runtime_error("SigScanner::SigScanner() - Could not find module " + moduleName);
         }

         MODULEINFO info;
         if (!GetModuleInformation(GetCurrentProcess(), ModuleHandle, &info, sizeof(info)))
         {
             throw std::runtime_error("SigScanner::SigScanner() - Could not get handle information.");
         }

         m_begin = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
         m_end = m_begin + info.SizeOfImage;
    }

    uintptr_t SigScanner::FindSignature(const char* pSignature, const std::string& mask)
    {
        const uintptr_t LastScan = m_end - mask.length() + 1;
        for (auto address = m_begin; address < LastScan; ++address)
        {
            for (size_t i = 0;; ++i)
            {
                if (mask[i] == 0)
                {
                    return address;
                }

                if (mask[i] != '?' && pSignature[i] != *(reinterpret_cast<char*>(address + i)))
                {
                    break;
                }
            }
        }

        return 0;
    }
}}

