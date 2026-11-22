namespace DLLHijackHunter.Safety;

/// <summary>What the guard needs to know about a service. Pure data, no registry access.</summary>
public sealed record ServiceFacts(string Name, string? ImagePath = null, string? ServiceDllPath = null,
    int LaunchProtected = 0);

/// <summary>Decides whether the tool may stop or restart a service.</summary>
public static class ServiceGuard
{
    // 9c91eab behaviour: no service is guarded.
    public static (bool guarded, string reason) IsGuarded(ServiceFacts svc) => (false, "");

    public static (bool guarded, string reason) IsGuarded(string serviceName) => (false, "");

    public static bool IsSecurityProductImage(string? imagePath) => false;

    public static IReadOnlyList<ThirdPartyEntry> ThirdPartyEntries => Array.Empty<ThirdPartyEntry>();
}

/// <summary>One third-party EDR/AV service name, with the public vendor page that names it.</summary>
public sealed record ThirdPartyEntry(string Name, string Vendor, string Source)
{
}
