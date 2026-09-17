using DLLHijackHunter.Models;
using System.Text;
using System.Web;

namespace DLLHijackHunter.Reporting;

public static class HtmlReportTemplate
{
    public static string Generate(ScanResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine(@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>DLLHijackHunter Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  .header { text-align: center; margin-bottom: 2rem; }
  .header h1 { font-size: 2.5rem; color: #58a6ff; margin-bottom: 0.5rem; }
  .header .subtitle { color: #8b949e; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; text-align: center; }
  .summary-card .value { font-size: 2rem; font-weight: bold; margin-bottom: 0.25rem; }
  .summary-card .label { color: #8b949e; font-size: 0.9rem; }
  .tier-confirmed .value { color: #f85149; }
  .tier-high .value { color: #d29922; }
  .tier-medium .value { color: #e3b341; }
  .tier-low .value { color: #8b949e; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; }
  .finding-header.confirmed { background: rgba(248, 81, 73, 0.1); border-bottom: 2px solid #f85149; }
  .finding-header.high { background: rgba(210, 153, 34, 0.1); border-bottom: 2px solid #d29922; }
  .finding-header.medium { background: rgba(227, 179, 65, 0.1); border-bottom: 2px solid #e3b341; }
  .finding-header.low { background: rgba(139, 148, 158, 0.1); border-bottom: 2px solid #8b949e; }
  .finding-body { padding: 1.5rem; }
  .finding-body .row { display: grid; grid-template-columns: 140px 1fr; margin-bottom: 0.5rem; }
  .finding-body .label { color: #8b949e; font-weight: 600; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }
  .badge-confirmed { background: #f85149; color: white; }
  .badge-high { background: #d29922; color: white; }
  .badge-medium { background: #e3b341; color: #1c1e21; }
  .badge-low { background: #8b949e; color: white; }
  .badge-phantom { background: #a371f7; color: white; }
  .badge-searchorder { background: #58a6ff; color: white; }
  .notes { margin-top: 1rem; padding: 1rem; background: #0d1117; border-radius: 4px; font-size: 0.9rem; }
  .notes li { margin-bottom: 0.25rem; color: #8b949e; }
  .score { font-size: 1.5rem; font-weight: bold; }
</style>
</head>
<body>
<div class=""header"">
  <h1>🔍 DLLHijackHunter</h1>
  <p class=""subtitle"">Automated DLL Hijacking Detection Report</p>
</div>");

        // Summary cards
        sb.AppendLine($@"
<div class=""summary"">
  <div class=""summary-card"">
    <div class=""value"">{result.Hostname}</div>
    <div class=""label"">Hostname</div>
  </div>
  <div class=""summary-card"">
    <div class=""value"">{result.TotalCandidatesDiscovered}</div>
    <div class=""label"">Candidates Scanned</div>
  </div>
  <div class=""summary-card tier-confirmed"">
    <div class=""value"">{result.Confirmed.Count}</div>
    <div class=""label"">Confirmed</div>
  </div>
  <div class=""summary-card tier-high"">
    <div class=""value"">{result.High.Count}</div>
    <div class=""label"">High</div>
  </div>
  <div class=""summary-card tier-medium"">
    <div class=""value"">{result.Medium.Count}</div>
    <div class=""label"">Medium</div>
  </div>
  <div class=""summary-card tier-low"">
    <div class=""value"">{result.Low.Count}</div>
    <div class=""label"">Low</div>
  </div>
</div>");

        // Findings
        int rank = 0;
        foreach (var f in result.AllFindings)
        {
            rank++;
            string tierCss = f.Tier.ToString().ToLower();
            string tierBadge = f.Tier.ToString().ToUpper();

            sb.AppendLine($@"
<div class=""finding"">
  <div class=""finding-header {tierCss}"">
    <div>
      <span class=""badge badge-{tierCss}"">{tierBadge}</span>
      <span class=""badge badge-{(f.Type == HijackType.Phantom ? "phantom" : "searchorder")}"">{f.Type}</span>
      <strong>#{rank}</strong> — {Enc(Path.GetFileName(f.BinaryPath))} → {Enc(f.DllName)}
    </div>
    <div class=""score"">{f.FinalScore:F1}</div>
  </div>
  <div class=""finding-body"">
    <div class=""row""><span class=""label"">Binary</span><span>{Enc(f.BinaryPath)}</span></div>
    <div class=""row""><span class=""label"">DLL</span><span>{Enc(f.DllName)}</span></div>
    <div class=""row""><span class=""label"">Hijack Path</span><span>{Enc(f.HijackWritablePath)}</span></div>
    <div class=""row""><span class=""label"">Trigger</span><span>{f.Trigger} ""{Enc(f.TriggerIdentifier)}""</span></div>
    <div class=""row""><span class=""label"">Runs As</span><span>{Enc(f.RunAsAccount)}</span></div>
    <div class=""row""><span class=""label"">Confidence</span><span>{f.Confidence:F0}%</span></div>
    <div class=""row""><span class=""label"">Impact</span><span>{f.ImpactScore:F1}</span></div>
    <div class=""row""><span class=""label"">Canary</span><span>{f.CanaryResult}" +
    (f.CanaryResult == CanaryResult.Fired ? $" ✓ ({Enc(f.ConfirmedPrivilege ?? "")} / {f.ConfirmedIntegrityLevel})" : "") +
    $@"</span></div>
    <div class=""row""><span class=""label"">Survives Reboot</span><span>{(f.SurvivesReboot ? "✓ Yes" : "No")}</span></div>
    <div class=""row""><span class=""label"">Use Cases</span><span>{(f.UseCases.Any() ? string.Join(", ", f.UseCases) : "General")}</span></div>");

            if (f.Notes.Any())
            {
                sb.AppendLine(@"    <ul class=""notes"">");
                foreach (var note in f.Notes)
                    sb.AppendLine($"      <li>{Enc(note)}</li>");
                sb.AppendLine("    </ul>");
            }

            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        sb.AppendLine($@"
            <div class=""footer"">
                <p>DLLHijackHunter v2.5.0 • Generated on {result.ScanDate:yyyy-MM-dd HH:mm:ss UTC}</p>
            </div>
        </body>
</html>");

        return sb.ToString();
    }

    private static string Enc(string s) => HttpUtility.HtmlEncode(s ?? "");
}