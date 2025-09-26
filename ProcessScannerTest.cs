using System;
using System.Linq;
using System.Threading.Tasks;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    class ProcessScannerTest
    {
        // Renamed to avoid conflict with WPF Main method
        static async Task TestMain(string[] args)
        {
            Console.WriteLine("🔍 Testing ProcessScanner...");
            
            var scanner = new ProcessScanner();
            
            try
            {
                Console.WriteLine("📊 Scanning processes...");
                var processes = await scanner.GetAllProcessesAsync();
                
                Console.WriteLine($"✅ Found {processes.Count} processes:");
                
                foreach (var process in processes.Take(10))
                {
                    Console.WriteLine($"  - {process.Name} (PID: {process.Id}) - {process.Description}");
                }
                
                if (processes.Count > 10)
                    Console.WriteLine($"  ... and {processes.Count - 10} more");
                
                Console.WriteLine($"\n🎯 Total: {processes.Count} processes found");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
                Console.WriteLine($"❌ Stack: {ex.StackTrace}");
            }
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
