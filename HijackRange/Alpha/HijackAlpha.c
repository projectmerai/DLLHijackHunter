/*
 * HijackRange — Alpha Scenario
 * Deliberately vulnerable Windows service for DLLHijackHunter lab demos.
 *
 * VULNERABILITY: This service statically imports alpha_payload.dll.
 * Windows resolves the import by searching the service binary directory
 * (C:\HijackRange\Alpha\) FIRST — and that directory has BUILTIN\Users:MODIFY.
 * Any non-admin user can plant a malicious DLL there; it runs as SYSTEM on
 * the next service (re)start.
 *
 * BUILD:  build-msvc.bat  (requires VS Build Tools / MSVC)
 *      or build-mingw.bat (requires MinGW-w64 / gcc)
 */

#include <windows.h>

/* AlphaInit() is exported by alpha_payload.dll — the hijack vector. */
__declspec(dllimport) void AlphaInit(void);

static SERVICE_STATUS        g_Status;
static SERVICE_STATUS_HANDLE g_Handle;
static HANDLE                g_StopEvent;

static void WINAPI CtrlHandler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_Handle, &g_Status);
        SetEvent(g_StopEvent);
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Handle    = RegisterServiceCtrlHandlerW(L"HijackRangeAlpha", CtrlHandler);

    g_Status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_Status.dwCurrentState     = SERVICE_RUNNING;
    SetServiceStatus(g_Handle, &g_Status);

    /*
     * DLL HIJACK VECTOR
     * alpha_payload.dll is resolved from C:\HijackRange\Alpha\ (the service's
     * own directory) which is writable by BUILTIN\Users.
     */
    AlphaInit();

    WaitForSingleObject(g_StopEvent, INFINITE);
    CloseHandle(g_StopEvent);
}

int main(void)
{
    SERVICE_TABLE_ENTRYW dispatch[] = {
        { L"HijackRangeAlpha", ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherW(dispatch);
    return 0;
}
