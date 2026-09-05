using System.Runtime.InteropServices;

namespace DLLHijackHunter.Native;

/// <summary>
/// Disables the legacy Windows console "QuickEdit Mode" for the lifetime of a scan and
/// restores the original console mode on dispose.
///
/// Why this exists: with QuickEdit Mode enabled (the conhost default), a single click
/// inside the console window puts it into mark/select mode. While selecting, the console
/// freezes its screen buffer and any process writing to stdout BLOCKS — so a long scan
/// appears to hang until the user presses a key (Space/Enter/Esc). Clearing
/// ENABLE_QUICK_EDIT_MODE (which requires ENABLE_EXTENDED_FLAGS to be set for the change
/// to take effect) prevents that stall. The original mode is restored on dispose so we
/// never leave the user's console changed after we exit — the mode change would otherwise
/// persist in a shared PowerShell window.
///
/// Trade-off: while a scan is running the user cannot click-drag to select text in the
/// window. That is intentional (selecting is what freezes the scan); normal copy/paste is
/// restored the moment the tool exits.
/// </summary>
public sealed class ConsoleQuickEdit : IDisposable
{
    private const int STD_INPUT_HANDLE = -10;
    private const uint ENABLE_EXTENDED_FLAGS = 0x0080;
    private const uint ENABLE_QUICK_EDIT_MODE = 0x0040;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    private readonly IntPtr _handle;
    private readonly uint _originalMode;
    private readonly bool _applied;
    private bool _restored;

    private ConsoleQuickEdit(IntPtr handle, uint originalMode)
    {
        _handle = handle;
        _originalMode = originalMode;
        _applied = true;
    }

    // No-op guard: no console, already disabled, or the mode change failed.
    private ConsoleQuickEdit() { }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    /// <summary>
    /// Disables QuickEdit Mode on the current console's input buffer, if there is one.
    /// Safe to call with no attached console (stdin redirected / detached) or on a
    /// non-Windows host — it returns a no-op guard instead of throwing.
    /// </summary>
    public static ConsoleQuickEdit Disable()
    {
        if (!OperatingSystem.IsWindows())
            return new ConsoleQuickEdit();

        try
        {
            IntPtr handle = GetStdHandle(STD_INPUT_HANDLE);
            if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
                return new ConsoleQuickEdit();

            // Fails when stdin isn't a real console (e.g. piped/redirected) — nothing to do.
            if (!GetConsoleMode(handle, out uint mode))
                return new ConsoleQuickEdit();

            uint newMode = (mode & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS;
            if (newMode == mode)
                return new ConsoleQuickEdit();            // QuickEdit already off
            if (!SetConsoleMode(handle, newMode))
                return new ConsoleQuickEdit();            // couldn't change; leave as-is

            return new ConsoleQuickEdit(handle, mode);    // applied; restore original on dispose
        }
        catch
        {
            // A console-mode tweak must never break the scan.
            return new ConsoleQuickEdit();
        }
    }

    public void Dispose()
    {
        if (!_applied || _restored)
            return;
        _restored = true;
        try { SetConsoleMode(_handle, _originalMode); }
        catch { /* best-effort restore */ }
    }
}
