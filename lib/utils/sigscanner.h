//
// For scanning signatures. This entire approach and pattern
// is inspired by the work of https://github.com/dantarion -- thanks!
//

#pragma once

#include <string>

namespace ReTools { namespace Utils
{
    class SigScanner
    {
    public:
        SigScanner(const std::string& moduleName);
        uintptr_t FindSignature(const char* pSignature, const std::string& mask);

    private:
        uintptr_t m_begin;
        uintptr_t m_end;
    };
}}

