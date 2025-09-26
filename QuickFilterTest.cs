using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using KeyloggerDetector.Models;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    class QuickFilterTest
    {
        static void TestFilterMain(string[] args)
        {
            Console.WriteLine("🧪 Testing Process Filter Backend Functionality");

            try
            {
                var processScanner = new ProcessScanner();
                var allProcesses = processScanner.GetAllProcessesAsync().Result;
    
    Console.WriteLine($"📋 Total processes found: {allProcesses.Count}");
    
    // Check threat level distribution first
    Console.WriteLine("\n🚨 Threat Level Distribution:");
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
    
    Console.WriteLine("\n✅ Backend filter testing completed!");
    
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
