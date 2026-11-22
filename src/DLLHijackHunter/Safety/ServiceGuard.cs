using System.Reflection;
using System.Text.Json;
using Microsoft.Win32;

namespace DLLHijackHunter.Safety;

/// <summary>What the guard needs to know about a service. Pure data, no registry access.</summary>
public sealed record ServiceFacts(string Name, string? ImagePath = null, string? ServiceDllPath = null,
    int LaunchProtected = 0);

/// <summary>One third-party EDR/AV service name, with the public vendor page that names it.</summary>
public sealed record ThirdPartyEntry(string Name, string Vendor, string Source);

/// <summary>
/// Decides whether the tool may stop or restart a service. A guarded service is never sent
/// <c>sc stop</c> (see <see cref="ServiceControl"/>) and gets no canary.
/// </summary>
public static class ServiceGuard
{
    /// <summary>Microsoft security services, by service name.</summary>
    internal static readonly IReadOnlySet<string> SecurityServiceNames = new HashSet<string>(
        new[]
        {
            "WinDefend", "WdNisSvc", "WdFilter", "WdBoot", "WdNisDrv", "Sense",
            "SecurityHealthService", "wscsvc", "MpsSvc", "BFE", "MDCoreSvc"
        }, StringComparer.OrdinalIgnoreCase);

    /// <summary>Folders whose binaries belong to Microsoft Defender (expanded at call time).</summary>
    internal static IReadOnlyList<string> SecurityProductRoots()
    {
        var roots = new List<string>();
        void AddUnder(Environment.SpecialFolder folder, string leaf)
        {
            string b = Environment.GetFolderPath(folder);
            if (!string.IsNullOrEmpty(b)) roots.Add(Path.Combine(b, leaf));
        }
        // "%ProgramFiles%\Windows Defender*" is a prefix match, so it also covers
        // "Windows Defender Advanced Threat Protection".
        AddUnder(Environment.SpecialFolder.ProgramFiles, "Windows Defender");
        AddUnder(Environment.SpecialFolder.ProgramFilesX86, "Windows Defender");
        AddUnder(Environment.SpecialFolder.CommonApplicationData, @"Microsoft\Windows Defender\Platform");
        return roots;
    }

    private static readonly Lazy<IReadOnlyList<ThirdPartyEntry>> _thirdParty = new(LoadThirdParty);

    /// <summary>Third-party EDR/AV names from the embedded Resources/security_services.json.</summary>
    public static IReadOnlyList<ThirdPartyEntry> ThirdPartyEntries => _thirdParty.Value;

    private static IReadOnlyList<ThirdPartyEntry> LoadThirdParty()
    {
        var list = new List<ThirdPartyEntry>();
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            string? name = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("security_services.json", StringComparison.OrdinalIgnoreCase));
            if (name == null) return list;
            using var s = asm.GetManifestResourceStream(name)!;
            using var doc = JsonDocument.Parse(s);
            foreach (var e in doc.RootElement.GetProperty("services").EnumerateArray())
            {
                list.Add(new ThirdPartyEntry(
                    e.GetProperty("name").GetString() ?? "",
                    e.GetProperty("vendor").GetString() ?? "",
                    e.GetProperty("source").GetString() ?? ""));
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Warn($"Could not load the embedded security-service list: {ex.Message}");
        }
        return list;
    }

    /// <summary>True when <paramref name="imagePath"/> lies under a Defender folder.</summary>
    public static bool IsSecurityProductImage(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath) || !Path.IsPathRooted(imagePath)) return false;
        string p;
        try { p = Path.GetFullPath(imagePath); } catch { return false; }
        foreach (var root in SecurityProductRoots())
            if (p.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;   // prefix: "Windows Defender*"
        return false;
    }

    /// <summary>The one decision function. Pure: uses only <paramref name="svc"/> and the embedded list.</summary>
    public static (bool guarded, string reason) IsGuarded(ServiceFacts svc)
    {
        if (string.IsNullOrWhiteSpace(svc.Name)) return (false, "");

        if (SecurityServiceNames.Contains(svc.Name))
            return (true, $"'{svc.Name}' is a Microsoft security service");

        var tp = ThirdPartyEntries.FirstOrDefault(e => e.Name.Equals(svc.Name, StringComparison.OrdinalIgnoreCase));
        if (tp != null)
            return (true, $"'{svc.Name}' is a {tp.Vendor} security service");

        if (svc.LaunchProtected != 0)
            return (true, $"'{svc.Name}' has LaunchProtected={svc.LaunchProtected} (protected service)");

        if (IsSecurityProductImage(svc.ImagePath))
            return (true, $"'{svc.Name}' runs a security-product binary ({svc.ImagePath})");
        if (IsSecurityProductImage(svc.ServiceDllPath))
            return (true, $"'{svc.Name}' hosts a security-product DLL ({svc.ServiceDllPath})");

        return (false, "");
    }

    /// <summary>
    /// Live decision for a service name: name checks first, then LaunchProtected / ImagePath /
    /// ServiceDll read from the registry the same way <see cref="Discovery.ServiceEnumerator"/> does.
    /// If the key cannot be read, only the name checks apply.
    /// </summary>
    public static (bool guarded, string reason) IsGuarded(string serviceName)
    {
        var byName = IsGuarded(new ServiceFacts(serviceName));
        if (byName.guarded) return byName;
        return IsGuarded(ReadFacts(serviceName));
    }

    internal static ServiceFacts ReadFacts(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            if (key == null) return new ServiceFacts(serviceName);
            int lp = key.GetValue("LaunchProtected") is int v ? v : 0;
            string? image = key.GetValue("ImagePath") is string raw
                ? Discovery.CommandLineParser.ExtractExecutablePath(
                    Environment.ExpandEnvironmentVariables(raw.Trim()))
                : null;
            string? serviceDll = null;
            using (var p = key.OpenSubKey("Parameters"))
                if (p?.GetValue("ServiceDll") is string dll)
                    serviceDll = Environment.ExpandEnvironmentVariables(dll);
            return new ServiceFacts(serviceName, image, serviceDll, lp);
        }
        catch
        {
            return new ServiceFacts(serviceName);
        }
    }
}
