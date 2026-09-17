/*
 * HijackRange — Beta Scenario
 * Deliberately vulnerable scheduled-task binary for DLLHijackHunter lab demos.
 *
 * VULNERABILITY: Statically imports beta_plugin.dll.
 * The task runs as SYSTEM with working directory C:\HijackRange\Beta\, which
 * has BUILTIN\Users:MODIFY — any user can plant a DLL there.
 * Demonstrates the SCHEDULED TASK trigger path.
 */
#include <windows.h>

__declspec(dllimport) void BetaInit(void);

int main(void)
{
    BetaInit();
    return 0;
}
