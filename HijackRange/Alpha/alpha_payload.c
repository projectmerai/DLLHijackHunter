/*
 * HijackRange — Alpha Payload (benign stub DLL)
 * The LEGITIMATE version of alpha_payload.dll shipped with the lab.
 * DLLHijackHunter backs this up, drops the canary in its place, confirms
 * SYSTEM execution, then restores this original automatically.
 */
#include <windows.h>

__declspec(dllexport) void AlphaInit(void)
{
    /* benign stub */
}

BOOL WINAPI DllMain(HINSTANCE hMod, DWORD reason, LPVOID reserved)
{
    (void)hMod; (void)reason; (void)reserved;
    return TRUE;
}
