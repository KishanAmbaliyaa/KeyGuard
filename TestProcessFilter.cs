using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using KeyloggerDetector.Models;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    public class TestProcessFilter
    {
        public static void TestMain(string[] args)
        {
            Console.WriteLine("🧪 Testing Process Filter Functionality");
            
            try
            {
                var processScanner = new ProcessScanner();
                var allProcesses = processScanner.GetAllProcessesAsync().Result;
                
                Console.WriteLine($"📋 Total processes found: {allProcesses.Count}");
                
                // Check threat level distribution first
                Console.WriteLine("\n� Threat Level Distribution:");
                var threatLevels = allProcesses.GroupBy(p => p.ThreatLevel).OrderBy(g => g.Key);
                foreach (var group in threatLevels)
                {
                    Console.WriteLine($"  {group.Key}: {group.Count()} processes");
                    if (group.Count() <= 5)
                    {
                        foreach (var proc in group.Take(3))
                        {
                            Console.WriteLine($"    - {proc.Name} (PID: {proc.Id})");
                        }
                    }
                }
                
                // Test filtering by "Medium" threat level
                Console.WriteLine("\n🔍 Testing Medium Threat Filter:");
                var mediumThreatProcesses = allProcesses.Where(p => 
                    p.ThreatLevel.Equals("Medium", StringComparison.OrdinalIgnoreCase)).ToList();
                Console.WriteLine($"Medium threat processes: {mediumThreatProcesses.Count}");
                foreach (var process in mediumThreatProcesses.Take(5))
                {
                    Console.WriteLine($"  - {process.Name} (PID: {process.Id}, Threat: {process.ThreatLevel})");
                }
                
                // Test process type filtering
                Console.WriteLine("\n🏷️ Process Type Distribution:");
                var processTypes = allProcesses.GroupBy(p => p.ProcessType).OrderBy(g => g.Key);
                foreach (var group in processTypes)
                {
                    Console.WriteLine($"  {group.Key}: {group.Count()} processes");
                }
                
                // Test filtering by "User" processes
                Console.WriteLine("\n🔍 Testing User Process Filter:");
                var userProcesses = allProcesses.Where(p => p.ProcessType == "User").ToList();
                Console.WriteLine($"User processes: {userProcesses.Count}");
                foreach (var process in userProcesses.Take(5))
                {
                    Console.WriteLine($"  - {process.Name} (PID: {process.Id}, Type: {process.ProcessType})");
                }
                
                // Test search filtering
                Console.WriteLine("\n� Testing Search Filter for 'chrome':");
                var searchTerm = "chrome";
                var filteredBySearch = allProcesses.Where(p => 
                    p.Name.ToLowerInvariant().Contains(searchTerm) ||
                    (!string.IsNullOrEmpty(p.Path) && p.Path.ToLowerInvariant().Contains(searchTerm))
                ).ToList();
                
                Console.WriteLine($"Search for '{searchTerm}': {filteredBySearch.Count} matches");
                foreach (var process in filteredBySearch.Take(5))
                {
                    Console.WriteLine($"  - {process.Name} (PID: {process.Id}, Path: {process.Path})");
                }
                
                Console.WriteLine("\n✅ Filter testing completed!");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
