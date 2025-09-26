using KeyloggerDetector.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading.Tasks;

namespace KeyloggerDetector.Services
{
    /// <summary>
    /// Hierarchical process scanner that builds parent-child relationships
    /// and categorizes processes like Windows 11 Task Manager
    /// </summary>
    public class HierarchicalProcessScanner
    {
        private readonly ProcessScanner _baseScanner;
        private readonly ThreatDetector _threatDetector;

        public HierarchicalProcessScanner()
        {
            _baseScanner = new ProcessScanner();
            _threatDetector = new ThreatDetector();
        }

        /// <summary>
        /// Scans all processes and builds hierarchical tree with categories
        /// </summary>
        public async Task<ObservableCollection<ProcessNodeViewModel>> ScanProcessHierarchyAsync(IProgress<string> progress = null)
        {
            return await Task.Run(async () =>
            {
                progress?.Report("Scanning system processes...");

                // Step 1: Get all processes with full details
                var allProcesses = await _baseScanner.GetAllProcessesAsync();
                progress?.Report("Building process relationships...");

                // Step 2: Get parent-child relationships using WMI
                var parentChildMap = await GetParentChildRelationshipsAsync();
                progress?.Report("Categorizing processes...");

                // Step 3: Create ProcessNodeViewModel for each process
                var processNodes = new Dictionary<int, ProcessNodeViewModel>();
                var rootNodes = new List<ProcessNodeViewModel>();

                foreach (var processInfo in allProcesses)
                {
                    try
                    {
                        // Enhance with threat detection
                        var threatLevel = await _threatDetector.AnalyzeProcessAsync(processInfo);
                        processInfo.ThreatLevel = threatLevel.ToString();
                        processInfo.IsSuspicious = threatLevel != ThreatLevel.Low;

                        // Create node
                        var node = new ProcessNodeViewModel(processInfo)
                        {
                            Category = CategorizeProcess(processInfo)
                        };

                        processNodes[processInfo.Id] = node;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error processing {processInfo.Name}: {ex.Message}");
                    }
                }

                progress?.Report("Building hierarchy...");

                // Step 4: Build the hierarchy and create service groups
                var serviceGroups = new Dictionary<string, ProcessNodeViewModel>();
                
                foreach (var kvp in processNodes)
                {
                    var processId = kvp.Key;
                    var node = kvp.Value;
                    var processName = node.ProcessDetails.Name.ToLowerInvariant();

                    // NO GROUPING - Show all processes individually like user requested
                    // Every process gets its own entry, even if there are 10 Chrome instances

                    // Check if this process has a parent (non-service processes)
                    if (parentChildMap.TryGetValue(processId, out var parentId) && 
                        processNodes.TryGetValue(parentId, out var parentNode))
                    {
                        // Only create parent-child relationship if parent isn't a grouped service
                        if (!ShouldGroupProcess(parentNode.ProcessDetails.Name.ToLowerInvariant()))
                        {
                            // Add as child to parent
                            parentNode.Children.Add(node);
                            node.IndentLevel = 1;
                            continue;
                        }
                    }
                    
                    // No valid parent found, this is a root process
                    rootNodes.Add(node);
                    node.IndentLevel = 0;
                }

                // Step 5: Update group display names with counts
                foreach (var group in serviceGroups.Values)
                {
                    var childCount = group.Children.Count;
                    group.ProcessDetails.Name = $"{group.ProcessDetails.Name} ({childCount})";
                }

                // Step 5: Refresh display properties and sort
                foreach (var node in processNodes.Values)
                {
                    node.RefreshDisplayProperties();
                }

                // Sort root nodes by category, then by name
                var sortedRoots = rootNodes
                    .OrderBy(n => GetCategoryOrder(n.Category))
                    .ThenBy(n => n.ProcessDetails.Name)
                    .ToList();

                // Sort children within each parent
                foreach (var parent in processNodes.Values.Where(n => n.HasChildren))
                {
                    var sortedChildren = parent.Children
                        .OrderBy(c => c.ProcessDetails.Name)
                        .ToList();
                    
                    parent.Children.Clear();
                    foreach (var child in sortedChildren)
                    {
                        parent.Children.Add(child);
                    }
                }

                progress?.Report($"Found {processNodes.Count} processes in hierarchy");

                Debug.WriteLine($"📊 HIERARCHICAL SCANNER RESULTS:");
                Debug.WriteLine($"   • Input processes: {allProcesses.Count}");
                Debug.WriteLine($"   • Process nodes created: {processNodes.Count}");
                Debug.WriteLine($"   • Root nodes (visible): {sortedRoots.Count}");
                Debug.WriteLine($"   • Expected ~284 total processes");
                
                if (processNodes.Count < allProcesses.Count)
                {
                    Debug.WriteLine($"⚠️  PROCESS LOSS: {allProcesses.Count - processNodes.Count} processes lost during hierarchy building!");
                }

                return new ObservableCollection<ProcessNodeViewModel>(sortedRoots);
            });
        }

        /// <summary>
        /// Uses WMI to get parent-child process relationships
        /// </summary>
        private async Task<Dictionary<int, int>> GetParentChildRelationshipsAsync()
        {
            return await Task.Run(() =>
            {
                var parentChildMap = new Dictionary<int, int>();

                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        "SELECT ProcessId, ParentProcessId FROM Win32_Process"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            try
                            {
                                var processId = Convert.ToInt32(obj["ProcessId"]);
                                var parentProcessId = Convert.ToInt32(obj["ParentProcessId"]);
                                
                                if (processId != parentProcessId) // Avoid self-references
                                {
                                    parentChildMap[processId] = parentProcessId;
                                }
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"Error parsing WMI process data: {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"WMI query failed: {ex.Message}");
                    // Fallback: no parent-child relationships
                }

                return parentChildMap;
            });
        }

        /// <summary>
        /// Categorizes processes like Windows 11 Task Manager
        /// </summary>
        private string CategorizeProcess(ProcessInfo processInfo)
        {
            try
            {
                // Get the actual Process object for additional checks
                var process = Process.GetProcessById(processInfo.Id);

                // Apps: Processes with visible windows (user applications)
                if (process.MainWindowHandle != IntPtr.Zero && !string.IsNullOrEmpty(process.MainWindowTitle))
                {
                    return "Apps";
                }

                // Check for well-known app processes even without visible windows
                var appProcessNames = new[]
                {
                    "chrome", "firefox", "msedge", "notepad", "winword", "excel", "powerpnt",
                    "outlook", "teams", "slack", "discord", "spotify", "steam", "vlc",
                    "photoshop", "illustrator", "code", "devenv", "notepad++", "calculatorapp",
                    "mspaint", "cmd", "powershell", "explorer"
                };

                var processName = processInfo.Name.ToLowerInvariant();
                if (appProcessNames.Any(app => processName.Contains(app)))
                {
                    return "Apps";
                }

                // Windows processes: Critical system processes
                if (IsWindowsSystemProcess(processInfo))
                {
                    return "Windows processes";
                }

                // Everything else is background processes (services, drivers, etc.)
                return "Background processes";
            }
            catch
            {
                // If we can't determine, categorize based on name patterns
                var name = processInfo.Name.ToLowerInvariant();
                
                // Known system processes
                if (name.Contains("system") || name.Contains("winlogon") || name.Contains("csrss") ||
                    name.Contains("lsass") || name.Contains("services") || name.Contains("dwm") ||
                    name.Contains("wininit") || name.Contains("smss"))
                {
                    return "Windows processes";
                }
                
                // Default to background
                return "Background processes";
            }
        }

        /// <summary>
        /// Determines if a process should be grouped with similar processes
        /// </summary>
        private bool ShouldGroupProcess(string processName)
        {
            // Only group the most common service processes to reduce grouping and show more individual processes
            var groupableProcesses = new[]
            {
                "svchost", // Only group svchost processes as they are very numerous
                "chrome", "firefox", "msedge" // Browser processes with many tabs
            };

            return groupableProcesses.Any(group => processName.Contains(group));
        }

        /// <summary>
        /// Gets the display name for a service group
        /// </summary>
        private string GetServiceGroupName(string processName)
        {
            if (processName.Contains("svchost")) return "Service Host";
            if (processName.Contains("rundll32")) return "Windows Host Process";
            if (processName.Contains("conhost")) return "Console Window Host";
            if (processName.Contains("dllhost")) return "COM Surrogate";
            if (processName.Contains("runtimebroker")) return "Runtime Broker";
            if (processName.Contains("backgroundtaskhost")) return "Background Task Host";
            if (processName.Contains("taskhostw")) return "Task Host Window";
            if (processName.Contains("chrome")) return "Google Chrome";
            if (processName.Contains("firefox")) return "Mozilla Firefox";
            if (processName.Contains("msedge")) return "Microsoft Edge";
            
            // Default: capitalize first letter
            return char.ToUpper(processName[0]) + processName.Substring(1);
        }

        /// <summary>
        /// Determines if a process is a Windows system process
        /// </summary>
        private bool IsWindowsSystemProcess(ProcessInfo processInfo)
        {
            if (string.IsNullOrEmpty(processInfo.Path))
                return false;

            var windowsPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);

            // Check if process is in Windows or System32 directory
            var path = processInfo.Path.ToLowerInvariant();
            var isInWindowsDir = path.StartsWith(windowsPath.ToLowerInvariant());
            var isInSystemDir = path.StartsWith(systemPath.ToLowerInvariant());

            // Known critical system process names
            var criticalSystemProcesses = new[]
            {
                "system", "idle", "winlogon", "csrss", "lsass", "services", "spoolsv",
                "dwm", "audiodg", "svchost", "wininit", "smss", "winload", "ntoskrnl",
                "registry", "memory compression", "secure system", "conhost"
            };

            var processName = processInfo.Name.ToLowerInvariant();
            var isCriticalSystem = criticalSystemProcesses.Any(name => 
                processName.Contains(name) || processName.Equals(name));

            return (isInWindowsDir || isInSystemDir || isCriticalSystem);
        }

        /// <summary>
        /// Gets sort order for categories
        /// </summary>
        private int GetCategoryOrder(string category)
        {
            return category switch
            {
                "Apps" => 0,
                "Background processes" => 1,
                "Windows processes" => 2,
                _ => 3
            };
        }
    }
}
