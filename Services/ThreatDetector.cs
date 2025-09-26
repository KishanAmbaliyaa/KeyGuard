using KeyloggerDetector.Models;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace KeyloggerDetector.Services
{
    public class ThreatDetector
    {
        private readonly string[] _knownKeyloggers = {
            "keylogger", "spyware", "stealer", "logger", "capture", "recorder",
            "hook", "spy", "monitor", "track", "sniff", "backdoor", "input", "keyboard"
        };

        private readonly string[] _suspiciousProcesses = {
            "rundll32", "powershell", "cmd", "wscript", "cscript"
        };

        private readonly string[] _legitimateProcesses = {
            "explorer", "winlogon", "csrss", "system", "services", "lsass",
            "dwm", "svchost", "audiodg", "conhost"
        };

        public ThreatDetector()
        {
            // Advanced rule-based detector with AI-inspired scoring
        }

        public async Task<ThreatLevel> AnalyzeProcessAsync(ProcessInfo processInfo)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var threatScore = 0;
                    
                    // Rule-based threat detection
                    
                    // Check process name against known keylogger patterns
                    var processNameLower = processInfo.Name.ToLower();
                    if (_knownKeyloggers.Any(keyword => processNameLower.Contains(keyword)))
                    {
                        threatScore += 50;
                    }
                    
                    // Check for keyboard hooks
                    if (processInfo.HasKeyboardHooks)
                    {
                        threatScore += 30;
                    }
                    
                    // Check for system access
                    if (processInfo.HasSystemAccess)
                    {
                        threatScore += 20;
                    }
                    
                    // Check for suspicious process behavior
                    if (IsSuspiciousProcess(processInfo))
                    {
                        threatScore += 25;
                    }
                    
                    // Check file location
                    if (IsInSuspiciousLocation(processInfo.Path))
                    {
                        threatScore += 15;
                    }
                    
                    // Check if process has no description or suspicious description
                    if (string.IsNullOrEmpty(processInfo.Description) || 
                        processInfo.Description.ToLower().Contains("unknown") ||
                        processInfo.Description.ToLower().Contains("access denied"))
                    {
                        threatScore += 10;
                    }
                    
                    // Determine threat level based on score
                    return threatScore switch
                    {
                        >= 80 => ThreatLevel.Critical,
                        >= 60 => ThreatLevel.High,
                        >= 35 => ThreatLevel.Medium, 
                        >= 15 => ThreatLevel.Low,
                        _ => ThreatLevel.Safe
                    };
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error analyzing process {processInfo.Name}: {ex.Message}");
                    return ThreatLevel.Safe;
                }
            });
        }

        private bool IsSuspiciousProcess(ProcessInfo processInfo)
        {
            // Check if it's a known legitimate process first
            if (_legitimateProcesses.Contains(processInfo.Name.ToLower()) && 
                IsInLegitimateLocation(processInfo.Path))
            {
                return false;
            }
            
            // Check for processes with generic names running from unusual locations
            if (_suspiciousProcesses.Contains(processInfo.Name.ToLower()))
            {
                return true;
            }
            
            // Check for unsigned or suspicious executables
            if (processInfo.Path.ToLower().Contains("temp") ||
                processInfo.Path.ToLower().Contains("appdata\\roaming") ||
                processInfo.Path.ToLower().Contains("downloads"))
            {
                return true;
            }
            
            return false;
        }

        private bool IsInLegitimateLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            
            var pathLower = path.ToLower();
            var legitimateLocations = new[]
            {
                "\\windows\\system32\\",
                "\\windows\\syswow64\\",
                "\\program files\\",
                "\\program files (x86)\\",
                "\\windows\\",
                "c:\\windows\\"
            };
            
            return legitimateLocations.Any(location => pathLower.Contains(location));
        }

        private bool IsInSuspiciousLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            
            var pathLower = path.ToLower();
            var suspiciousLocations = new[]
            {
                "\\temp\\",
                "\\appdata\\roaming\\",
                "\\downloads\\",
                "\\desktop\\",
                "\\documents\\",
                "\\public\\",
                "\\users\\public\\",
                "\\$recycle.bin\\",
                "\\recycler\\"
            };
            
            return suspiciousLocations.Any(location => pathLower.Contains(location));
        }

        public ThreatLevel AnalyzeFile(string filePath)
        {
            try
            {
                var threatScore = 0;
                var fileName = Path.GetFileName(filePath).ToLower();
                var fileExtension = Path.GetExtension(filePath).ToLower();
                
                // Check file name against known malware patterns
                if (_knownKeyloggers.Any(keyword => fileName.Contains(keyword)))
                {
                    threatScore += 50;
                }
                
                // Check for suspicious file extensions
                var suspiciousExtensions = new[] { ".exe", ".scr", ".bat", ".cmd", ".pif", ".com", ".vbs", ".js", ".jar" };
                if (suspiciousExtensions.Contains(fileExtension))
                {
                    threatScore += 20;
                }
                
                // Check file location
                if (IsInSuspiciousLocation(filePath))
                {
                    threatScore += 30;
                }
                
                // Check file size (very small or very large executables can be suspicious)
                var fileInfo = new FileInfo(filePath);
                if (fileExtension == ".exe")
                {
                    if (fileInfo.Length < 1024) // Very small executable
                        threatScore += 25;
                    else if (fileInfo.Length > 100 * 1024 * 1024) // Very large executable
                        threatScore += 15;
                }
                
                // Check for hidden or system files in user directories
                if ((fileInfo.Attributes & FileAttributes.Hidden) != 0 && 
                    filePath.ToLower().Contains("\\users\\"))
                {
                    threatScore += 20;
                }
                
                // Convert score to threat level
                return threatScore switch
                {
                    >= 80 => ThreatLevel.Critical,
                    >= 60 => ThreatLevel.High,
                    >= 40 => ThreatLevel.Medium,
                    >= 20 => ThreatLevel.Low,
                    _ => ThreatLevel.Safe
                };
            }
            catch
            {
                return ThreatLevel.Safe;
            }
        }
    }
}
