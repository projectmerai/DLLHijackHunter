using System;
using System.IO;

namespace DLLHijackHunter.Discovery
{
    public static class CommandLineParser
    {
        /// <summary>
        /// Best-effort parsing of a Windows command line to extract the target executable path.
        /// Handles quoted paths, unquoted paths with spaces, and environment variables.
        /// Heuristically unwraps common host processes (cmd, powershell, rundll32) to find the true payload.
        /// Note: This is an OS-level heuristic parser. Perfect command-line matching across all Windows 
        /// escaping edge cases is not guaranteed.
        /// </summary>
        public static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return string.Empty;
            }

            string targetPath = ExtractFirstToken(commandLine, out string arguments);
            
            if (string.IsNullOrWhiteSpace(targetPath)) return string.Empty;

            // Best-effort OS heuristic unwrapper
            string lowerPath = targetPath.ToLowerInvariant();
            string fileName = Path.GetFileName(lowerPath);

            if (fileName == "cmd.exe" || fileName == "cmd")
            {
                // look for /c or /k
                int cIdx = arguments.IndexOf("/c ", StringComparison.OrdinalIgnoreCase);
                if (cIdx < 0) cIdx = arguments.IndexOf("/k ", StringComparison.OrdinalIgnoreCase);
                
                if (cIdx >= 0)
                {
                    string innerCmd = arguments.Substring(cIdx + 3).Trim();
                    if (innerCmd.StartsWith("\"") && innerCmd.EndsWith("\""))
                    {
                        innerCmd = innerCmd.Substring(1, innerCmd.Length - 2).Trim();
                    }
                    return ExtractExecutablePath(innerCmd); // Recursive unwrap
                }
            }
            else if (fileName == "powershell.exe" || fileName == "powershell" || fileName == "pwsh.exe" || fileName == "pwsh")
            {
                // look for -file or -f
                int fIdx = arguments.IndexOf("-file ", StringComparison.OrdinalIgnoreCase);
                if (fIdx >= 0)
                {
                    string innerCmd = arguments.Substring(fIdx + 6).Trim();
                    return ExtractFirstToken(innerCmd, out _);
                }

                fIdx = arguments.IndexOf("-f ", StringComparison.OrdinalIgnoreCase);
                if (fIdx >= 0)
                {
                    string innerCmd = arguments.Substring(fIdx + 3).Trim();
                    return ExtractFirstToken(innerCmd, out _);
                }

                // look for -command or -c
                int cIdx = arguments.IndexOf("-command ", StringComparison.OrdinalIgnoreCase);
                if (cIdx >= 0)
                {
                    string innerCmd = arguments.Substring(cIdx + 9).Trim();
                    if (innerCmd.StartsWith("\"") && innerCmd.EndsWith("\""))
                        innerCmd = innerCmd.Substring(1, innerCmd.Length - 2).Trim();
                    else if (innerCmd.StartsWith("'") && innerCmd.EndsWith("'"))
                        innerCmd = innerCmd.Substring(1, innerCmd.Length - 2).Trim();
                        
                    return ExtractExecutablePath(innerCmd);
                }
                
                cIdx = arguments.IndexOf("-c ", StringComparison.OrdinalIgnoreCase);
                if (cIdx >= 0)
                {
                    string innerCmd = arguments.Substring(cIdx + 3).Trim();
                    if (innerCmd.StartsWith("\"") && innerCmd.EndsWith("\""))
                        innerCmd = innerCmd.Substring(1, innerCmd.Length - 2).Trim();
                    else if (innerCmd.StartsWith("'") && innerCmd.EndsWith("'"))
                        innerCmd = innerCmd.Substring(1, innerCmd.Length - 2).Trim();
                        
                    return ExtractExecutablePath(innerCmd);
                }
            }
            else if (fileName == "rundll32.exe" || fileName == "rundll32")
            {
                // rundll32 path\to\dll,Export [args]
                // Quoted:   "C:\Program Files\x\a.dll",Run   → token parser handles it.
                // Unquoted: C:\Program Files\x\a.dll,Run     → the DLL path ends at the first
                //           comma, not the first space, so split on the comma first.
                string argsTrim = arguments.Trim();
                string innerDll;
                int firstComma = argsTrim.IndexOf(',');
                if (!argsTrim.StartsWith("\"") && firstComma > 0 &&
                    File.Exists(Environment.ExpandEnvironmentVariables(argsTrim.Substring(0, firstComma).Trim())))
                {
                    innerDll = Environment.ExpandEnvironmentVariables(argsTrim.Substring(0, firstComma).Trim());
                }
                else
                {
                    innerDll = ExtractFirstToken(argsTrim, out _);
                    int commaIdx = innerDll.IndexOf(',');
                    if (commaIdx > 0)
                    {
                        innerDll = innerDll.Substring(0, commaIdx);
                    }
                }
                return innerDll.Trim().Trim('"');
            }

            return targetPath;
        }

        private static string ExtractFirstToken(string commandLine, out string remainingArguments)
        {
            commandLine = commandLine.Trim();
            remainingArguments = string.Empty;
            string path = string.Empty;

            if (commandLine.StartsWith("\""))
            {
                int endQuote = commandLine.IndexOf("\"", 1);
                if (endQuote > 0)
                {
                    path = commandLine.Substring(1, endQuote - 1);
                    if (commandLine.Length > endQuote + 1)
                        remainingArguments = commandLine.Substring(endQuote + 1).Trim();
                }
                else
                {
                    path = commandLine.Substring(1);
                }
            }
            else
            {
                // Unquoted paths - take up to the first space
                int firstSpace = commandLine.IndexOf(" ");
                if (firstSpace > 0)
                {
                    path = commandLine.Substring(0, firstSpace);
                    remainingArguments = commandLine.Substring(firstSpace + 1).Trim();
                    
                    // Best-effort unquoted path resolution (e.g. C:\Program Files\App.exe)
                    string progressivePath = path;
                    string[] remainingParts = remainingArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    int partIdx = 0;
                    
                    while (!File.Exists(Environment.ExpandEnvironmentVariables(progressivePath)) && 
                           !File.Exists(Environment.ExpandEnvironmentVariables(progressivePath) + ".exe") &&
                           partIdx < remainingParts.Length)
                    {
                        progressivePath += " " + remainingParts[partIdx];
                        partIdx++;
                    }

                    if (File.Exists(Environment.ExpandEnvironmentVariables(progressivePath)) || 
                        File.Exists(Environment.ExpandEnvironmentVariables(progressivePath) + ".exe"))
                    {
                        // Return the name that actually exists on disk: when only "<path>.exe"
                        // matched, the extension-less path would fail every later File.Exists.
                        path = File.Exists(Environment.ExpandEnvironmentVariables(progressivePath))
                            ? progressivePath
                            : progressivePath + ".exe";
                        
                        // Rebuild remaining args
                        if (partIdx < remainingParts.Length)
                            remainingArguments = string.Join(" ", remainingParts, partIdx, remainingParts.Length - partIdx);
                        else
                            remainingArguments = string.Empty;
                    }
                }
                else
                {
                    path = commandLine;
                }
            }

            return Environment.ExpandEnvironmentVariables(path);
        }
    }
}
