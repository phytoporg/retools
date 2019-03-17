#include <windows.h>
#include <utils/sigscanner.h>
#include <iomanip>

#include <sstream>
#include <fstream>

extern "C"
{
    uintptr_t OriginalBlockAddress;
}

extern "C" void DumpCharacterState(char* pCharPtr)
{
    const bool CharacterInactive = pCharPtr[12] != 0;
    if (CharacterInactive)
    {
        return;
    }

    const auto PlayerNumber = static_cast<int>(pCharPtr[4]) + 1;

    static char* CharacterNameTable[] = {
        "Hyde",
        "Linne",
        "Waldstein",
        "Carmine",
        "Orie",
        "Gordeau",
        "Merkava",
        "Vatista",
        "Seth",
        "Yuzuriha",
        "Hilda",
        "Eltnum",
        "Nanase",
        "Byakuya",
        "Akatsuki",
        "Chaos",
        "Wagner",
        "Enkidu",
        "NA",
        "NA",
        "NA",
        "Mika",
        "NA",
        "NA",
        "Phonon"
    };

    char characterSelected = pCharPtr[5];
    int health = *(int*)(pCharPtr + 0x64);

    static std::ofstream out("data.txt");
    out << "Player: " << PlayerNumber << "\n"
        << "Char: "   << CharacterNameTable[characterSelected] << "\n"
        << "Health: " << health << "\n" << std::endl;
}

__declspec(naked) void DumpCharHook()
{
    __asm
    {
        push        ecx                // The parameter stack location is manipulated in DumpCharacterState()
        push        ecx                // ECX contains pointer to character data structure
        call        DumpCharacterState

        pop         ecx
        pop         ecx

        // Original, overwritten code
        xor         eax, eax
        push        edi
        mov         edi, ecx
        mov         byte ptr [edi+000001B6h],0

        // Jump back. Next reference to ecx is a movezx ecx, byte ptr[...]
        // so we're safe to clobber it here.
        mov         ecx, OriginalBlockAddress
        jmp         ecx
    }
}

uintptr_t insert_jmp(uintptr_t addr, uintptr_t dest)
{
    constexpr auto PatchSize = 12;

    DWORD old_protect;
    VirtualProtect((void*)(addr), PatchSize, PAGE_EXECUTE_READWRITE, &old_protect);

    //
    // 0:  b8 00 00 00 00          mov    eax, 0x0
    // 5 : ff e0                   jmp    eax
    // Then a bunch of NOPs
    //

    *( BYTE*)(addr)     = 0xB8; // mov eax, dest
    *(DWORD*)(addr + 1) = dest;

    *( BYTE*)(addr + 5) = 0xFF;
    *( BYTE*)(addr + 6) = 0xE0;

    // We're in the middle of a mov instruction, just fill the rest with NOPs
    memset(reinterpret_cast<void*>(addr + 7), 0x90, 5); 

    VirtualProtect((void*)(addr), PatchSize, old_protect, &old_protect);

    return addr + PatchSize;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void* pReserved)
{
    if (reason != DLL_PROCESS_ATTACH) { return FALSE; }

    using namespace ReTools::Utils;
    SigScanner scanner("UNIst.exe");

    const uintptr_t Address = scanner.FindSignature("\xC6\x87\x9B\x01\x00\x00\x00", "xxxxxxx");
    if (Address != 0)
    {
        OriginalBlockAddress = insert_jmp(Address - 0xC, reinterpret_cast<uintptr_t>(DumpCharHook));
    }

    return TRUE;
}

