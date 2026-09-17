using System.Collections.Concurrent;
using PeNet;
using PeNet.Header.Pe;

namespace DLLHijackHunter.Discovery;

public class PEAnalyzer
{
    // PE analysis is deterministic for a given file path during a read-only scan
    // and is invoked once per candidate by several filters. Memoizing avoids the
    // repeated 2 MB raw reads and authenticode verification that dominated wall-clock.
    private static readonly ConcurrentDictionary<string, PEAnalysisResult> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Get all DLLs imported by a PE file (standard imports + delay loads).
    /// Results are memoized by file path for the lifetime of the process.
    /// </summary>
    public static PEAnalysisResult Analyze(string filePath)
        => _cache.GetOrAdd(filePath, AnalyzeUncached);

    private static PEAnalysisResult AnalyzeUncached(string filePath)
    {
        var result = new PEAnalysisResult { FilePath = filePath };

        try
        {
            var pe = new PeFile(filePath);

            // Standard imports
            if (pe.ImportedFunctions != null)
            {
                foreach (var func in pe.ImportedFunctions)
                {
                    if (!string.IsNullOrEmpty(func.DLL))
                        result.ImportedDlls.Add(func.DLL.ToLowerInvariant());
                }
            }

            // Delay-loaded imports
            try
            {
                var dataDirs = pe.ImageNtHeaders?.OptionalHeader?.DataDirectory;
                // Index 13 is Delay Import Directory
                if (dataDirs != null && dataDirs.Length > 13 && pe.ImageSectionHeaders != null)
                {
                    var delayDir = dataDirs[13];
                    if (delayDir.VirtualAddress != 0 && delayDir.Size != 0)
                    {
                        // RVA to File Offset helper
                        Func<uint, uint> RvaToOffset = rva =>
                        {
                            foreach (var sec in pe.ImageSectionHeaders)
                            {
                                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize)
                                {
                                    // Defensive check: If the RVA places us past the initialized raw data
                                    // of the section (e.g. into BSS or unmapped padding), it has no physical file offset
                                    uint offsetInSection = rva - sec.VirtualAddress;
                                    if (offsetInSection >= sec.SizeOfRawData) return 0;

                                    return offsetInSection + sec.PointerToRawData;
                                }
                            }
                            return 0;
                        };

                        uint delayOffset = RvaToOffset(delayDir.VirtualAddress);
                        if (delayOffset != 0)
                        {
                            using var stream = new System.IO.FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
                            using var reader = new System.IO.BinaryReader(stream);
                            stream.Position = delayOffset;
                            
                            while (stream.Position < delayOffset + delayDir.Size && stream.Position + 32 <= stream.Length)
                            {
                                uint attrs = reader.ReadUInt32();
                                uint nameRva = reader.ReadUInt32();
                                reader.ReadUInt32(); // hmod
                                reader.ReadUInt32(); // delayIat
                                reader.ReadUInt32(); // delayInt
                                reader.ReadUInt32(); // boundIat
                                reader.ReadUInt32(); // unloadIat
                                reader.ReadUInt32(); // timeStamp
                                
                                if (nameRva == 0) break; // null descriptor terminates the array
                                
                                uint nameOffset = RvaToOffset(nameRva);
                                if (nameOffset != 0 && nameOffset < stream.Length)
                                {
                                    long savedPos = stream.Position;
                                    stream.Position = nameOffset;
                                    var bytes = new System.Collections.Generic.List<byte>();
                                    byte b;
                                    while (stream.Position < stream.Length && (b = reader.ReadByte()) != 0 && bytes.Count < 256) bytes.Add(b);
                                    
                                    string dllName = System.Text.Encoding.ASCII.GetString(bytes.ToArray());
                                    if (!string.IsNullOrEmpty(dllName))
                                    {
                                        result.DelayLoadDlls.Add(dllName.ToLowerInvariant());
                                        // We no longer remove from ImportedDlls to avoid data loss 
                                        // if a DLL is listed in both standard and delay-load tables.
                                    }
                                    stream.Position = savedPos;
                                }
                            }
                        }
                    }
                }
            }
            catch { /* Some PEs have malformed delay imports */ }

            // Check for embedded manifest
            CheckForManifest(pe, filePath, result);

            // Check for LoadLibrary calls (heuristic from import table)
            if (pe.ImportedFunctions != null)
            {
                var funcNames = pe.ImportedFunctions
                    .Where(f => !string.IsNullOrEmpty(f.Name))
                    .Select(f => f.Name!)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                result.UsesLoadLibrary = funcNames.Any(n =>
                    n.Contains("LoadLibrary", StringComparison.OrdinalIgnoreCase));

                result.UsesLoadLibraryEx = funcNames.Any(n =>
                    n.Contains("LoadLibraryEx", StringComparison.OrdinalIgnoreCase));

                result.CallsSetDllDirectory = funcNames.Any(n =>
                    n.Contains("SetDllDirectory", StringComparison.OrdinalIgnoreCase));

                result.CallsSetDefaultDllDirectories = funcNames.Any(n =>
                    n.Contains("SetDefaultDllDirectories", StringComparison.OrdinalIgnoreCase));

                result.CallsAddDllDirectory = funcNames.Any(n =>
                    n.Contains("AddDllDirectory", StringComparison.OrdinalIgnoreCase));
            }

            // Get exported functions (for DLL proxy generation)
            try
            {
                if (pe.ExportedFunctions != null)
                {
                    result.Exports = pe.ExportedFunctions
                        .Where(e => !string.IsNullOrEmpty(e.Name))
                        .Select(e => e.Name!)
                        .ToList();
                }
            }
            catch { }

            // Is 64-bit?
            result.Is64Bit = pe.Is64Bit;

            // Is signed? - Check if authenticode signature exists
            try
            {
                result.IsSigned = pe.HasValidAuthenticodeSignature;
            }
            catch
            {
                // Fallback: check if signature directory exists
                try
                {
                    result.IsSigned = pe.ImageNtHeaders?.OptionalHeader?.DataDirectory != null &&
                        pe.ImageNtHeaders.OptionalHeader.DataDirectory.Length > 4 &&
                        pe.ImageNtHeaders.OptionalHeader.DataDirectory[4].VirtualAddress != 0;
                }
                catch
                {
                    result.IsSigned = false;
                }
            }

            // Check DllCharacteristics for FORCE_INTEGRITY
            try
            {
                if (pe.ImageNtHeaders?.OptionalHeader != null)
                {
                    var chars = pe.ImageNtHeaders.OptionalHeader.DllCharacteristics;
                    // Cast enum to ushort for bitwise operations
                    result.ForceIntegrity = ((ushort)chars & 0x0080) != 0;
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            result.AnalysisError = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Get exports from a DLL file (for proxy DLL generation).
    /// </summary>
    public static List<string> GetExports(string dllPath)
    {
        try
        {
            var pe = new PeFile(dllPath);
            return pe.ExportedFunctions?
                .Where(e => !string.IsNullOrEmpty(e.Name))
                .Select(e => e.Name!)
                .ToList() ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Get exports from a DLL file with both name and ordinal, including ordinal-only exports
    /// (where <see cref="ExportEntry.Name"/> is null). Used by the runtime export-forwarding
    /// proxy so every export — named or ordinal-only — gets a correct forwarder.
    /// </summary>
    public static List<ExportEntry> GetExportEntries(string dllPath)
    {
        var list = new List<ExportEntry>();
        try
        {
            var pe = new PeFile(dllPath);
            if (pe.ExportedFunctions != null)
            {
                foreach (var e in pe.ExportedFunctions)
                {
                    // A forwarder in the ORIGINAL still exposes a name/ordinal we must re-forward.
                    list.Add(new ExportEntry
                    {
                        Name = string.IsNullOrEmpty(e.Name) ? null : e.Name,
                        Ordinal = (ushort)e.Ordinal
                    });
                }
            }
        }
        catch
        {
        }
        return list;
    }

    /// <summary>
    /// Checks for an embedded manifest using multiple methods.
    /// </summary>
    private static void CheckForManifest(PeFile pe, string filePath, PEAnalysisResult result)
    {
        result.HasEmbeddedManifest = false;
        
        // Method 1: Check resource directory for RT_MANIFEST (type 24)
        try
        {
            var resourceDir = pe.ImageResourceDirectory;
            if (resourceDir?.DirectoryEntries != null)
            {
                foreach (var entry in resourceDir.DirectoryEntries)
                {
                    if (entry == null) continue;
                    try
                    {
                        // PeNet 4.x uses NameResolved property
                        if (entry.NameResolved != null &&
                            entry.NameResolved.Equals("RT_MANIFEST", StringComparison.OrdinalIgnoreCase))
                        {
                            result.HasEmbeddedManifest = true;
                            // Optionally extract from resources here, but fallback to string search is fine
                        }
                        
                        // Also check numeric ID (24 = RT_MANIFEST)
                        // In PeNet 4.x, Name can be numeric string
                        if (entry.IsIdEntry && entry.ID == 24)
                        {
                            result.HasEmbeddedManifest = true;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Method 2: Search raw bytes for manifest XML signature
        // HEURISTIC WARNING: Doing raw string matching across the PE rather than rigorous
        // RT_MANIFEST resource parsing. This is a best-effort fallback heuristic.
        try
        {
            byte[] rawBytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                // Read at most 2MB to search for manifest
                int readSize = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
                rawBytes = new byte[readSize];
                fs.Read(rawBytes, 0, readSize);
            }

            string content = System.Text.Encoding.UTF8.GetString(rawBytes);
            
            // Extract manifest bounded by <assembly> and </assembly>
            int startIndex = content.IndexOf("<assembly", StringComparison.OrdinalIgnoreCase);
            if (startIndex >= 0)
            {
                int endIndex = content.IndexOf("</assembly>", startIndex, StringComparison.OrdinalIgnoreCase);
                if (endIndex > 0)
                {
                    result.ManifestContent = content.Substring(startIndex, endIndex - startIndex + 11);
                    result.HasEmbeddedManifest = true;
                }
            }

            if (content.Contains("assembly xmlns", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("assemblyIdentity", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("trustInfo xmlns", StringComparison.OrdinalIgnoreCase))
            {
                result.HasEmbeddedManifest = true;
            }
        }
        catch { }

        // Method 3: Check for external manifest file
        string externalManifest = filePath + ".manifest";
        if (File.Exists(externalManifest))
        {
            result.HasEmbeddedManifest = true;
            try { result.ManifestContent = File.ReadAllText(externalManifest); } catch { }
        }
    }
}

/// <summary>
/// A single PE export: its name (null for ordinal-only exports) and its (biased) ordinal.
/// </summary>
public class ExportEntry
{
    public string? Name { get; set; }
    public ushort Ordinal { get; set; }
}

public class PEAnalysisResult
{
    public string FilePath { get; set; } = "";
    public HashSet<string> ImportedDlls { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> DelayLoadDlls { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool HasEmbeddedManifest { get; set; }
    public string? ManifestContent { get; set; }
    public bool UsesLoadLibrary { get; set; }
    public bool UsesLoadLibraryEx { get; set; }
    public bool CallsSetDllDirectory { get; set; }
    public bool CallsSetDefaultDllDirectories { get; set; }
    public bool CallsAddDllDirectory { get; set; }
    public List<string> Exports { get; set; } = new();
    public bool Is64Bit { get; set; }
    public bool IsSigned { get; set; }
    public bool ForceIntegrity { get; set; }
    public string? AnalysisError { get; set; }

    private HashSet<string>? _allImportedDlls;
    public HashSet<string> AllImportedDlls =>
        _allImportedDlls ??= new(ImportedDlls.Concat(DelayLoadDlls), StringComparer.OrdinalIgnoreCase);
}