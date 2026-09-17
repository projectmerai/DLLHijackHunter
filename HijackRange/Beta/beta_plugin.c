/*
 * HijackRange — Beta Plugin (benign stub DLL)
 */
#include <windows.h>

__declspec(dllexport) void BetaInit(void)
{
    /* benign stub */
}

BOOL WINAPI DllMain(HINSTANCE hMod, DWORD reason, LPVOID reserved)
{
    (void)hMod; (void)reason; (void)reserved;
    return TRUE;
}
