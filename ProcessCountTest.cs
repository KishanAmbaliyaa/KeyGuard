using System;
using System.Diagnostics;
using System.Linq;

namespace KeyloggerDetector
{
    class ProcessCountTest
    {
        static void TestProcessCount(string[] args)
        {
            Console.WriteLine("🔍 Process Count Diagnostic Test");
            Console.WriteLine("================================");
            
            try
            {
                // Test 1: Direct Process.GetProcesses()
                var allProcesses = Process.GetProcesses();
                Console.WriteLine($"✅ Process.GetProcesses() found: {allProcesses.Length} processes");
                
                // Test 2: Count accessible processes
                int accessibleCount = 0;
                int inaccessibleCount = 0;
                
                foreach (var process in allProcesses)
                {
                    try
                    {
                        var name = process.ProcessName; // Try to access basic info
                        var id = process.Id;
                        accessibleCount++;
                    }
                    catch
                    {
                        inaccessibleCount++;
                    }
                }
                
                Console.WriteLine($"✅ Accessible processes: {accessibleCount}");
                Console.WriteLine($"⚠️  Inaccessible processes: {inaccessibleCount}");
                Console.WriteLine($"📊 Total: {accessibleCount + inaccessibleCount}");
                
                // Test 3: Show some sample process names
                Console.WriteLine("\n📝 Sample processes found:");
                var sampleProcesses = allProcesses.Take(10);
                foreach (var process in sampleProcesses)
                {
                    try
                    {
                        Console.WriteLine($"   • {process.ProcessName} (PID: {process.Id})");
                    }
                    catch
                    {
                        Console.WriteLine($"   • [Inaccessible] (PID: {process.Id})");
                    }
                }
                
                Console.WriteLine($"\nExpected: ~284 processes");
                Console.WriteLine($"Found: {allProcesses.Length} processes");
                
                if (allProcesses.Length < 200)
                {
                    Console.WriteLine("❌ PROBLEM: Significantly fewer processes found than expected!");
                }
                else
                {
                    Console.WriteLine("✅ Process count looks normal");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error during test: {ex.Message}");
            }
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
