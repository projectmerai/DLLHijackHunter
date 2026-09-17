using DLLHijackHunter.Discovery;

namespace DLLHijackHunter.Canary;

/// <summary>
/// Synthesizes an export-forwarding proxy DLL at runtime with NO compiler.
///
/// Takes the embedded, precompiled canary (whose <c>DllMain</c> self-locates and writes the
/// confirmation file) and grafts on a freshly-built export directory whose every export is a
/// PE *forwarder* string of the form <c>"&lt;forwardModuleBase&gt;.&lt;ExportName&gt;"</c> (or
/// <c>"&lt;forwardModuleBase&gt;.#&lt;Ordinal&gt;"</c> for ordinal-only exports). The forwarders
/// point at a sidecar copy of the original DLL, so a host that binds those exports at load time
/// (a static import) resolves them, the process starts, <c>DllMain</c> fires, and host
/// functionality is preserved.
///
/// Why this exists: the export-less precompiled canary makes any load-time named import fail at
/// import-snap (<c>STATUS_ENTRYPOINT_NOT_FOUND</c>, 0xC0000139) BEFORE DllMain runs — which is
/// why service/task candidates that statically import their DLL always timed out. The old
/// export-preserving path needed an MSVC toolchain (cl.exe/vcvarsall); this one needs nothing.
///
/// PE surgery: append one new section (".edata") holding the export directory + tables + strings,
/// point DataDirectory[EXPORT] at it, bump NumberOfSections/SizeOfImage. Existing sections are
/// untouched (no relocation), so the base canary's code/DllMain are preserved verbatim.
/// </summary>
public static class RuntimeProxyBuilder
{
    private const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    private const uint IMAGE_SCN_MEM_READ = 0x40000000;

    /// <summary>
    /// Build an export-forwarding proxy from a base canary PE.
    /// </summary>
    /// <param name="baseCanary">Bytes of the embedded precompiled canary (matching the victim
    /// bitness). Its DllMain writes the confirmation; only its export directory is replaced.</param>
    /// <param name="forwardModuleBase">Module base name (no extension) the forwarders target,
    /// i.e. the sidecar filename without ".dll" — e.g. "beta_plugin.hhorig".</param>
    /// <param name="exports">Exports of the ORIGINAL DLL (name + ordinal).</param>
    /// <param name="proxyBytes">The synthesized proxy DLL on success.</param>
    /// <returns>false if synthesis is not possible (caller must NOT deploy an export-less DLL
    /// over a named-import target — fall back and flag instead).</returns>
    public static bool TryBuild(byte[] baseCanary, string forwardModuleBase,
        IReadOnlyList<ExportEntry> exports, out byte[] proxyBytes)
    {
        proxyBytes = Array.Empty<byte>();
        try
        {
            if (baseCanary is not { Length: >= 0x200 } || exports is null || exports.Count == 0
                || string.IsNullOrEmpty(forwardModuleBase))
                return false;

            byte[] pe = (byte[])baseCanary.Clone();

            // --- Parse headers ---
            if (pe[0] != (byte)'M' || pe[1] != (byte)'Z') return false;
            int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 0x18 > pe.Length) return false;
            if (BitConverter.ToUInt32(pe, e_lfanew) != 0x00004550) return false; // "PE\0\0"

            int fileHeader = e_lfanew + 4;
            ushort numberOfSections = BitConverter.ToUInt16(pe, fileHeader + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(pe, fileHeader + 16);
            int optHeader = fileHeader + 20;
            if (optHeader + sizeOfOptionalHeader > pe.Length || numberOfSections == 0) return false;

            ushort magic = BitConverter.ToUInt16(pe, optHeader);
            bool is64 = magic == 0x20B;                       // PE32+ vs PE32
            uint sectionAlignment = BitConverter.ToUInt32(pe, optHeader + 32);
            uint fileAlignment = BitConverter.ToUInt32(pe, optHeader + 36);
            if (sectionAlignment == 0 || fileAlignment == 0) return false;
            uint sizeOfHeaders = BitConverter.ToUInt32(pe, optHeader + 60);

            // DataDirectory begins at a different offset for PE32 vs PE32+.
            int dataDirOffset = optHeader + (is64 ? 112 : 96); // DataDirectory[0] = EXPORT
            int sectionTable = optHeader + sizeOfOptionalHeader;

            // Highest virtual address end across existing sections.
            uint maxVaEnd = 0;
            for (int i = 0; i < numberOfSections; i++)
            {
                int sh = sectionTable + i * 40;
                uint vsize = BitConverter.ToUInt32(pe, sh + 8);
                uint vaddr = BitConverter.ToUInt32(pe, sh + 12);
                uint rawSize = BitConverter.ToUInt32(pe, sh + 16);
                uint veEnd = vaddr + Math.Max(vsize, rawSize);
                if (veEnd > maxVaEnd) maxVaEnd = veEnd;
            }

            // Need room in the header for one more IMAGE_SECTION_HEADER before SizeOfHeaders.
            int newSectionHeaderOff = sectionTable + numberOfSections * 40;
            if ((uint)(newSectionHeaderOff + 40) > sizeOfHeaders) return false;

            uint newSecVA = Align(maxVaEnd, sectionAlignment);

            // --- Build the export blob laid out at newSecVA ---
            byte[] blob = BuildExportBlob(forwardModuleBase, exports, newSecVA);
            uint blobLen = (uint)blob.Length;

            // Place the blob after ALL existing file content (guards against an overlay).
            uint newRawPtr = Align((uint)pe.Length, fileAlignment);
            uint newRawSize = Align(blobLen, fileAlignment);

            var outBytes = new byte[newRawPtr + newRawSize];
            Array.Copy(pe, 0, outBytes, 0, pe.Length);
            Array.Copy(blob, 0, outBytes, (int)newRawPtr, blob.Length);

            // --- Patch headers ---
            WriteU16(outBytes, fileHeader + 2, (ushort)(numberOfSections + 1)); // NumberOfSections
            WriteU32(outBytes, optHeader + 56, Align(newSecVA + blobLen, sectionAlignment)); // SizeOfImage
            // DataDirectory[EXPORT]: VA + Size. Size MUST span the whole blob (incl. forwarder
            // strings) or the loader will not treat the EAT entries as forwarders.
            WriteU32(outBytes, dataDirOffset, newSecVA);
            WriteU32(outBytes, dataDirOffset + 4, blobLen);
            WriteSectionHeader(outBytes, newSectionHeaderOff, ".edata",
                blobLen, newSecVA, newRawSize, newRawPtr,
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);

            proxyBytes = outBytes;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Lay out IMAGE_EXPORT_DIRECTORY + EAT + ENPT + name-ordinal table + strings as one blob,
    /// with every internal RVA relative to <paramref name="baseVA"/>.
    /// </summary>
    private static byte[] BuildExportBlob(string forwardModuleBase,
        IReadOnlyList<ExportEntry> exports, uint baseVA)
    {
        // Ordinal span.
        ushort minOrd = ushort.MaxValue, maxOrd = 0;
        foreach (var e in exports)
        {
            if (e.Ordinal < minOrd) minOrd = e.Ordinal;
            if (e.Ordinal > maxOrd) maxOrd = e.Ordinal;
        }
        uint ordinalBase = minOrd;
        int numFunctions = maxOrd - minOrd + 1;

        // Named exports MUST be sorted by name (loader binary-searches the name table).
        var named = exports.Where(e => !string.IsNullOrEmpty(e.Name))
                           .OrderBy(e => e.Name, StringComparer.Ordinal)
                           .ToList();
        int numNames = named.Count;

        // Fixed-size region offsets within the blob.
        int dirOff = 0;
        int eatOff = dirOff + 40;
        int enptOff = eatOff + numFunctions * 4;
        int ordOff = enptOff + numNames * 4;
        int stringsOff = ordOff + numNames * 2;

        // Strings are appended in call order; each returns its RVA.
        var strings = new List<byte>();
        uint AddString(string s)
        {
            uint rva = (uint)(baseVA + stringsOff + strings.Count);
            foreach (char c in s) strings.Add((byte)c);
            strings.Add(0);
            return rva;
        }

        uint moduleNameRva = AddString(forwardModuleBase + ".dll");

        // One forwarder string per ordinal slot (dedup by ordinal).
        var forwarderRvaByOrdinal = new Dictionary<ushort, uint>();
        foreach (var e in exports)
        {
            if (forwarderRvaByOrdinal.ContainsKey(e.Ordinal)) continue;
            string fwd = !string.IsNullOrEmpty(e.Name)
                ? $"{forwardModuleBase}.{e.Name}"
                : $"{forwardModuleBase}.#{e.Ordinal}";
            forwarderRvaByOrdinal[e.Ordinal] = AddString(fwd);
        }

        // Name string RVAs, in sorted order (parallel to `named`).
        var nameRvas = new List<uint>(numNames);
        foreach (var e in named) nameRvas.Add(AddString(e.Name!));

        var blob = new byte[stringsOff + strings.Count];

        // Export Address Table: slot (ord - base) -> forwarder RVA, gaps = 0.
        for (int i = 0; i < numFunctions; i++)
        {
            ushort ord = (ushort)(ordinalBase + i);
            uint rva = forwarderRvaByOrdinal.TryGetValue(ord, out var r) ? r : 0;
            WriteU32(blob, eatOff + i * 4, rva);
        }

        // Export Name Pointer Table + name-ordinal table.
        for (int i = 0; i < numNames; i++)
        {
            WriteU32(blob, enptOff + i * 4, nameRvas[i]);
            WriteU16(blob, ordOff + i * 2, (ushort)(named[i].Ordinal - ordinalBase));
        }

        Array.Copy(strings.ToArray(), 0, blob, stringsOff, strings.Count);

        // IMAGE_EXPORT_DIRECTORY.
        // +0  Characteristics(4)=0   +4 TimeDateStamp(4)=0   +8 Major/Minor(2+2)=0
        WriteU32(blob, dirOff + 12, moduleNameRva);              // Name
        WriteU32(blob, dirOff + 16, ordinalBase);               // Base
        WriteU32(blob, dirOff + 20, (uint)numFunctions);        // NumberOfFunctions
        WriteU32(blob, dirOff + 24, (uint)numNames);            // NumberOfNames
        WriteU32(blob, dirOff + 28, baseVA + (uint)eatOff);     // AddressOfFunctions
        WriteU32(blob, dirOff + 32, baseVA + (uint)enptOff);    // AddressOfNames
        WriteU32(blob, dirOff + 36, baseVA + (uint)ordOff);     // AddressOfNameOrdinals

        return blob;
    }

    private static uint Align(uint v, uint a) => ((v + a - 1) / a) * a;

    private static void WriteU16(byte[] b, int off, ushort v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
    }

    private static void WriteU32(byte[] b, int off, uint v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
        b[off + 2] = (byte)(v >> 16);
        b[off + 3] = (byte)(v >> 24);
    }

    private static void WriteSectionHeader(byte[] b, int off, string name,
        uint vsize, uint vaddr, uint rawSize, uint rawPtr, uint characteristics)
    {
        for (int i = 0; i < 8; i++)
            b[off + i] = i < name.Length ? (byte)name[i] : (byte)0;
        WriteU32(b, off + 8, vsize);   // VirtualSize
        WriteU32(b, off + 12, vaddr);  // VirtualAddress
        WriteU32(b, off + 16, rawSize);// SizeOfRawData
        WriteU32(b, off + 20, rawPtr); // PointerToRawData
        WriteU32(b, off + 24, 0);      // PointerToRelocations
        WriteU32(b, off + 28, 0);      // PointerToLinenumbers
        WriteU16(b, off + 32, 0);      // NumberOfRelocations
        WriteU16(b, off + 34, 0);      // NumberOfLinenumbers
        WriteU32(b, off + 36, characteristics);
    }
}
