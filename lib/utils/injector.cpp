#include "injector.h"
#include <stdexcept>
#include <TlHelp32.h>
#include <Psapi.h>

namespace ReTools { namespace Utils { 
    Injector::Injector(const std::string processName)
    : m_processHandle(INVALID_HANDLE_VALUE)
    {
        LUID luid;
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            HANDLE processToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &processToken))
            {
                if (!(AdjustTokenPrivileges(
                    processToken,
                    FALSE,
                    &tp,
                    0,
                    static_cast<PTOKEN_PRIVILEGES>(nullptr),
                    static_cast<DWORD*>(nullptr))))
                {
                    throw std::runtime_error("Injector::Injector - AdjustTokenPrivileges() failed.");
                }
            }
            else
            {
                throw std::runtime_error("Injector::Injector - OpenProcessToken() failed.");
            }
        }
        else
        {
            throw std::runtime_error("Injector::Injector - LookupPrivilegeValue() failed.");
        }

        const auto Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);

        Process32First(Snap, &processEntry);
        HANDLE processHandle = INVALID_HANDLE_VALUE;
        do
        {
            constexpr auto Mask = 
                PROCESS_QUERY_INFORMATION | 
                PROCESS_CREATE_THREAD |
                PROCESS_VM_OPERATION |
                PROCESS_VM_READ |
                PROCESS_VM_WRITE;

            processHandle = OpenProcess(Mask, FALSE, processEntry.th32ProcessID);
            char path[MAX_PATH];
            if (GetModuleFileNameEx(processHandle, nullptr, path, MAX_PATH) == 0)
            {
                CloseHandle(processHandle);
                processHandle = INVALID_HANDLE_VALUE;
                continue;
            }

            if (std::string(path).find(processName) == std::string::npos)
            {
                CloseHandle(processHandle);
                processHandle = INVALID_HANDLE_VALUE;
                continue;
            }

            break;

        } while(Process32Next(Snap, &processEntry));

        CloseHandle(Snap);

        m_processHandle = processHandle;
    }

    bool Injector::InjectDll(const std::string& dllPath)
    {
        if (m_processHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        const size_t PathSize = dllPath.size();
        LPVOID pBuffer = 
            VirtualAllocEx(
                m_processHandle, nullptr, PathSize,
                MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (pBuffer == nullptr)
        {
            return false;
        }

        if (!WriteProcessMemory(
            m_processHandle, pBuffer,
            dllPath.c_str(), PathSize,
            nullptr)) 
        {
            return false; 
        }

        LPVOID fnLoadLibrary = GetProcAddress(
            GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA"
        );
        if (fnLoadLibrary == nullptr)
        {
            return false;
        }

        HANDLE hThread = 
            CreateRemoteThread(
                    m_processHandle, nullptr, 0,
                    //reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
                    reinterpret_cast<LPTHREAD_START_ROUTINE>(fnLoadLibrary),
                    pBuffer, 0, nullptr);
        if (hThread == NULL) 
        { 
            return false;
        }

        WaitForSingleObject(hThread, 60000);

        return true;
    }
}}
