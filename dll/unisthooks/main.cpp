#include <windows.h>
#include <utils/sigscanner.h>
#include <iomanip>

#include <sstream>

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void* pReserved)
{
    if (reason != DLL_PROCESS_ATTACH) { return FALSE; }

    using namespace ReTools::Utils;
    SigScanner scanner("UNIst.exe");

    {
        const uintptr_t Address = scanner.FindSignature("\xC6\x87\x9B\x01\x00\x00\x00", "xxxxxxx");

        MessageBox(nullptr, "Success?", (Address != 0 ? "Yes" : "No"), MB_OK);
    }

    return TRUE;
}
