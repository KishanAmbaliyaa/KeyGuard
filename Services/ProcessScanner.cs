using KeyloggerDetector.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace KeyloggerDetector.Services
{
    public class ProcessScanner
    {
        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, System.Text.StringBuilder lpBaseName, uint nSize);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        public async Task<List<ProcessInfo>> GetAllProcessesAsync()
        {
            return await ScanAllProcessesAsync(null);
        }

        public async Task<List<ProcessInfo>> ScanAllProcessesAsync(IProgress<int> progress)
        {
            return await Task.Run(() =>
            {
                var processes = new List<ProcessInfo>();
                
                try
                {
                    // Get ALL processes including system processes - be maximally inclusive
                    var systemProcesses = Process.GetProcesses();
                    var totalProcesses = systemProcesses.Length;
                    
                    Debug.WriteLine($"Scanning {totalProcesses} total system processes (showing ALL like Task Manager)");
                    
                    for (int i = 0; i < systemProcesses.Length; i++)
                    {
                        var process = systemProcesses[i];
                        try
                        {
                            // Include EVERY SINGLE process - just like Task Manager
                            var processInfo = new ProcessInfo
                            {
                                Name = process.ProcessName ?? $"Process{process.Id}",
                                Id = process.Id,
                                Path = GetProcessPath(process),
                                HasKeyboardHooks = CheckForKeyboardHooks(process),
                                HasSystemAccess = CheckSystemAccess(process),
                                ThreatLevel = "Safe", // Will be updated by threat analysis
                                Description = GetProcessDescription(process),
                                ProcessType = CategorizeProcessType(GetProcessPath(process), process.ProcessName)
                            };

                            // Analyze threat level using ThreatDetector
                            try
                            {
                                var threatDetector = new ThreatDetector();
                                var threatLevel = threatDetector.AnalyzeProcessAsync(processInfo).Result;
                                processInfo.ThreatLevel = threatLevel.ToString();
                                Debug.WriteLine($"✅ Threat analysis for {processInfo.Name}: {processInfo.ThreatLevel}");
                            }
                            catch (Exception ex)
                            {
                                processInfo.ThreatLevel = "Safe"; // Default fallback
                                Debug.WriteLine($"❌ Threat analysis failed for {processInfo.Name}: {ex.Message}");
                            }

                            // Get CPU and Memory usage - be extremely permissive  
                            try
                            {
                                processInfo.CpuUsage = GetCpuUsage(process);
                                processInfo.MemoryUsage = process.WorkingSet64;
                            }
                            catch
                            {
                                // Default values for inaccessible processes - still include them!
                                processInfo.CpuUsage = 0;
                                processInfo.MemoryUsage = 0;
                            }

                            // ALWAYS add every process - no exceptions
                            processes.Add(processInfo);
                            
                            // Report progress
                            progress?.Report((i + 1) * 100 / totalProcesses);
                        }
                        catch (Exception)
                        {
                            // Even for completely inaccessible processes, force inclusion with minimal info
                            try
                            {
                                var basicProcessInfo = new ProcessInfo
                                {
                                    Name = process.ProcessName ?? $"System Process {process.Id}",
                                    Id = process.Id,
                                    Path = "System Process",
                                    HasKeyboardHooks = false,
                                    HasSystemAccess = false,
                                    ThreatLevel = "Safe",
                                    Description = "Access Denied",
                                    CpuUsage = 0,
                                    MemoryUsage = 0
                                };
                                processes.Add(basicProcessInfo);
                            }
                            catch
                            {
                                // Forcefully add even unknown processes with just PID
                                try
                                {
                                    var unknownProcessInfo = new ProcessInfo
                                    {
                                        Name = $"Unknown Process ({process.Id})",
                                        Id = process.Id,
                                        Path = "Unknown",
                                        HasKeyboardHooks = false,
                                        HasSystemAccess = false,
                                        ThreatLevel = "Safe",
                                        Description = "System Process",
                                        CpuUsage = 0,
                                        MemoryUsage = 0
                                    };
                                    processes.Add(unknownProcessInfo);
                                    Debug.WriteLine($"Added unknown process with PID: {process.Id}");
                                }
                                catch
                                {
                                    Debug.WriteLine($"Completely inaccessible process PID: {process.Id}");
                                }
                            }
                        }
                    }
                    
                    Debug.WriteLine($"🔍 INITIAL SCAN: {processes.Count} processes found");
                    
                    // Debug: Show some sample threat levels
                    var sampleProcesses = processes.Take(10).ToList();
                    Debug.WriteLine("📊 Sample threat levels assigned:");
                    foreach (var proc in sampleProcesses)
                    {
                        Debug.WriteLine($"  {proc.Name} (PID: {proc.Id}): {proc.ThreatLevel} | {proc.ProcessType}");
                    }
                    
                    // BONUS: Try WMI scan for additional processes that might be missed
                    try
                    {
                        var wmiProcesses = new System.Management.ManagementObjectSearcher(
                            "SELECT ProcessId, Name FROM Win32_Process").Get();
                        
                        var existingPids = new HashSet<int>(processes.Select(p => p.Id));
                        int wmiAdded = 0;
                        
                        foreach (System.Management.ManagementObject wmiProcess in wmiProcesses)
                        {
                            try
                            {
                                var pid = Convert.ToInt32(wmiProcess["ProcessId"]);
                                if (!existingPids.Contains(pid))
                                {
                                    // Found additional process via WMI
                                    var processName = wmiProcess["Name"]?.ToString() ?? $"WMI Process {pid}";
                                    var wmiProcessInfo = new ProcessInfo
                                    {
                                        Name = processName,
                                        Id = pid,
                                        Path = "WMI Discovered",
                                        HasKeyboardHooks = false,
                                        HasSystemAccess = false,
                                        ThreatLevel = "Safe", 
                                        Description = "WMI System Process",
                                        CpuUsage = 0,
                                        MemoryUsage = 0,
                                        ProcessType = CategorizeProcessType("WMI Discovered", processName)
                                    };
                                    processes.Add(wmiProcessInfo);
                                    existingPids.Add(pid);
                                    wmiAdded++;
                                }
                            }
                            catch { }
                        }
                        
                        if (wmiAdded > 0)
                            Debug.WriteLine($"📊 WMI BONUS SCAN: Found {wmiAdded} additional processes");
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"WMI supplementary scan failed: {ex.Message}");
                    }

                    Debug.WriteLine($"🎯 FINAL TOTAL: {processes.Count} processes (Maximum Discovery Mode)");
                    Debug.WriteLine($"🔍 EXPECTED: ~284 processes (PowerShell count)");
                    
                    if (processes.Count < 200)
                    {
                        Debug.WriteLine($"⚠️  WARNING: Only found {processes.Count} processes, expected ~284!");
                        Debug.WriteLine("🔧 This suggests processes are being filtered somewhere.");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error during process scanning: {ex.Message}");
                }

                return processes.OrderBy(p => p.Name).ToList();
            });
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Unknown";
            }
            catch
            {
                return "Access Denied";
            }
        }

        private bool CheckForKeyboardHooks(Process process)
        {
            try
            {
                // Check if process has loaded user32.dll (common for keyboard hooks)
                var processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)process.Id);
                if (processHandle != IntPtr.Zero)
                {
                    IntPtr[] modules = new IntPtr[1024];
                    uint modulesSize = (uint)(modules.Length * IntPtr.Size);
                    
                    if (EnumProcessModules(processHandle, modules, modulesSize, out uint needed))
                    {
                        int moduleCount = (int)(needed / IntPtr.Size);
                        for (int i = 0; i < moduleCount; i++)
                        {
                            var moduleName = new System.Text.StringBuilder(1024);
                            if (GetModuleBaseName(processHandle, modules[i], moduleName, (uint)moduleName.Capacity) > 0)
                            {
                                string name = moduleName.ToString().ToLower();
                                if (name.Contains("user32") || name.Contains("hook") || name.Contains("input"))
                                {
                                    CloseHandle(processHandle);
                                    return true;
                                }
                            }
                        }
                    }
                    CloseHandle(processHandle);
                }
            }
            catch
            {
                // Access denied or other error
            }
            
            return false;
        }

        private bool CheckSystemAccess(Process process)
        {
            try
            {
                // Check if process is running with elevated privileges
                var query = $"SELECT * FROM Win32_Process WHERE ProcessId = {process.Id}";
                using var searcher = new ManagementObjectSearcher(query);
                using var results = searcher.Get();
                
                foreach (ManagementObject result in results)
                {
                    var owner = new string[2];
                    result.InvokeMethod("GetOwner", owner);
                    
                    // Check if running as SYSTEM or Administrator
                    if (owner[0]?.ToUpper() == "SYSTEM" || owner[1]?.ToUpper().Contains("ADMINISTRATOR") == true)
                    {
                        return true;
                    }
                }
            }
            catch
            {
                // WMI access might be restricted
            }
            
            return false;
        }

        private string GetProcessDescription(Process process)
        {
            try
            {
                return process.MainModule?.FileVersionInfo?.FileDescription ?? "No description available";
            }
            catch
            {
                return "Access denied";
            }
        }

        private double GetCpuUsage(Process process)
        {
            try
            {
                // Simple CPU estimation - return random low values for demo
                // In real implementation, you'd use performance counters or WMI
                var random = new Random(process.Id);
                return Math.Round(random.NextDouble() * 5.0, 1); // 0-5% CPU usage
            }
            catch
            {
                return 0.0;
            }
        }

        public void TerminateProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                
                // Safety check - don't terminate critical system processes
                var criticalProcesses = new[] { "winlogon", "csrss", "smss", "explorer", "dwm", "lsass" };
                if (criticalProcesses.Contains(process.ProcessName.ToLower()))
                {
                    throw new InvalidOperationException("Cannot terminate critical system process");
                }
                
                process.Kill();
                process.WaitForExit(5000); // Wait up to 5 seconds
            }
            catch (ArgumentException)
            {
                throw new InvalidOperationException("Process not found or already terminated");
            }
        }

        private string CategorizeProcessType(string processPath, string processName)
        {
            try
            {
                if (string.IsNullOrEmpty(processPath))
                {
                    return "Unknown";
                }

                var pathLower = processPath.ToLower();
                var nameLower = processName?.ToLower() ?? "";

                // Handle WMI discovered processes based on process name
                if (pathLower == "wmi discovered")
                {
                    return IsSystemProcess(nameLower) ? "System" : "User";
                }

                // System Applications - running from Windows directories
                if (pathLower.StartsWith(@"c:\windows\system32\") ||
                    pathLower.StartsWith(@"c:\windows\syswow64\") ||
                    pathLower.StartsWith(@"c:\windows\") ||
                    IsSystemProcess(nameLower))
                {
                    return "System";
                }

                // User Applications - running from Program Files or user directories
                if (pathLower.StartsWith(@"c:\program files\") ||
                    pathLower.StartsWith(@"c:\program files (x86)\") ||
                    pathLower.Contains(@"\appdata\local\") && !pathLower.Contains(@"\temp\"))
                {
                    return "User";
                }

                // Unknown/Suspicious - in temp, downloads, or unusual locations
                if (pathLower.Contains(@"\temp\") ||
                    pathLower.Contains(@"\downloads\") ||
                    pathLower.Contains(@"\appdata\roaming\") ||
                    pathLower.StartsWith(@"c:\users\") && pathLower.Contains(@"\desktop\"))
                {
                    return "Unknown";
                }

                // Default for other locations
                return "User";
            }
            catch
            {
                return "Unknown";
            }
        }

        private bool IsSystemProcess(string processName)
        {
            var systemProcesses = new[]
            {
                "system", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
                "svchost", "dwm", "explorer", "audiodg", "conhost", "taskhostw",
                "spoolsv", "runtimebroker", "searchindexer", "wmiprvse"
            };

            return systemProcesses.Contains(processName);
        }

        public List<ProcessInfo> GetSuspiciousProcesses(List<ProcessInfo> allProcesses)
        {
            return allProcesses.Where(p => 
                p.HasKeyboardHooks || 
                p.ThreatLevel == "High" || 
                p.ThreatLevel == "Medium" ||
                p.IsSuspicious
            ).ToList();
        }
    }
}
