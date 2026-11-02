using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace DLLHijackHunter.Filters;

/// <summary>
/// HARD GATE: KnownDLLs are loaded from a shared section object cache.
/// The filesystem search order is NOT used for these DLLs.
/// NOTE: .local redirection bypassed KnownDLLs on Windows XP/2003, but this was
/// removed in Windows Vista. On modern Windows, KnownDLLs cannot be redirected
/// by .local files — DotLocal candidates for KnownDLLs are false positives.
/// </summary>
public class KnownDllsFilter : IHardGate
{
    public string Name => "KnownDLLs Cache";

    private readonly HashSet<string> _knownDlls;
    private readonly HashSet<string> _knownDlls32; // WoW64 KnownDLLs

    // The registry KnownDLLs list is only the SEED: at boot the session manager also maps the
    // dependencies of those DLLs into \KnownDlls, and ntdll.dll is always mapped into every
    // process before anything is searched. The object directory is what the loader consults.
    private static readonly Lazy<HashSet<string>> _allKnownDlls = new(() => BuildKnownDllSet(
        @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs", @"\KnownDlls"));
    private static readonly Lazy<HashSet<string>> _allKnownDlls32 = new(() => BuildKnownDllSet(
        @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32", @"\KnownDlls32"));

    /// <summary>Native + WoW64 KnownDLL names (registry seed ∪ \KnownDlls object directory ∪ ntdll).</summary>
    internal static bool IsKnownDll(string dllName) =>
        _allKnownDlls.Value.Contains(dllName) || _allKnownDlls32.Value.Contains(dllName);

    public KnownDllsFilter()
    {
        _knownDlls = _allKnownDlls.Value;
        _knownDlls32 = _allKnownDlls32.Value;
    }

    private static HashSet<string> BuildKnownDllSet(string registryPath, string objectDirectory)
    {
        var set = LoadKnownDlls(registryPath);
        set.Add("ntdll.dll");
        foreach (var name in EnumerateObjectDirectory(objectDirectory))
            if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                set.Add(name.ToLowerInvariant());
        return set;
    }

    /// <summary>Names of the section objects in a kernel object directory such as \KnownDlls.</summary>
    private static List<string> EnumerateObjectDirectory(string directory)
    {
        var names = new List<string>();
        IntPtr nameBuf = IntPtr.Zero, strPtr = IntPtr.Zero, handle = IntPtr.Zero, buffer = IntPtr.Zero;
        try
        {
            nameBuf = Marshal.StringToHGlobalUni(directory);
            var us = new NativeMethods.UNICODE_STRING
            {
                Length = (ushort)(directory.Length * 2),
                MaximumLength = (ushort)(directory.Length * 2 + 2),
                Buffer = nameBuf
            };
            strPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.UNICODE_STRING>());
            Marshal.StructureToPtr(us, strPtr, false);

            var oa = new NativeMethods.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<NativeMethods.OBJECT_ATTRIBUTES>(),
                ObjectName = strPtr,
                Attributes = 0x40 // OBJ_CASE_INSENSITIVE
            };
            int status = NativeMethods.NtOpenDirectoryObject(out handle, NativeMethods.DIRECTORY_QUERY, ref oa);
            if (status != NativeMethods.STATUS_SUCCESS)
            {
                ScanLogger.Debug($"KnownDLLs: NtOpenDirectoryObject({directory}) failed 0x{status:X8}");
                return names;
            }

            const int BufferSize = 4096;
            buffer = Marshal.AllocHGlobal(BufferSize);
            uint context = 0;
            bool restart = true;
            while (NativeMethods.NtQueryDirectoryObject(handle, buffer, BufferSize, true, restart,
                       ref context, out _) == NativeMethods.STATUS_SUCCESS)
            {
                restart = false;
                var info = Marshal.PtrToStructure<NativeMethods.OBJECT_DIRECTORY_INFORMATION>(buffer);
                if (info.Name.Buffer != IntPtr.Zero && info.Name.Length > 0)
                    names.Add(Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2));
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"KnownDLLs: could not enumerate {directory}: {ex.Message}");
        }
        finally
        {
            if (handle != IntPtr.Zero) NativeMethods.CloseHandle(handle);
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (strPtr != IntPtr.Zero) Marshal.FreeHGlobal(strPtr);
            if (nameBuf != IntPtr.Zero) Marshal.FreeHGlobal(nameBuf);
        }
        return names;
    }

    public List<HijackCandidate> Apply(List<HijackCandidate> candidates)
    {
        return candidates.Where(c =>
        {
            string dll = c.DllName.ToLowerInvariant();

            // Check both native and WoW64 KnownDLLs
            bool isKnownDll = _knownDlls.Contains(dll) || _knownDlls32.Contains(dll);

            // .local redirection does NOT bypass KnownDLLs on Windows Vista+.
            // KnownDLLs are served from the kernel object store (\KnownDlls\) and are
            // immune to .local files on modern Windows. Suppress only those as false
            // positives; .local redirection of a non-KnownDLL is still a valid vector.
            // (Windows XP/2003 were the exception; this tool targets Vista+ environments.)
            if (c.Type == HijackType.DotLocal)
            {
                if (isKnownDll)
                {
                    c.FilterResults["KnownDLLs"] = FilterResult.Failed;
                    return false;
                }

                c.FilterResults["KnownDLLs"] = FilterResult.Passed;
                return true;
            }

            if (isKnownDll)
            {
                c.FilterResults["KnownDLLs"] = FilterResult.Failed;
                return false;
            }

            c.FilterResults["KnownDLLs"] = FilterResult.Passed;
            return true;
        }).ToList();
    }

    public static HashSet<string> LoadKnownDlls(string registryPath)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(registryPath);
            if (key == null) return result;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName) as string;
                if (!string.IsNullOrEmpty(value))
                {
                    result.Add(value.ToLowerInvariant());
                }
            }
        }
        catch { }

        return result;
    }
}