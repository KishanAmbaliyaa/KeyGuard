using System;
using System.Threading;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    class TestGlobalKeyboardMonitoring
    {
        static void RunKeyboardTest(string[] args)
        {
            Console.WriteLine("🔐 KeyGuard Pro - Global Keyboard Monitoring Test");
            Console.WriteLine("================================================");
            Console.WriteLine();
            Console.WriteLine("This test will verify that the global keyboard monitoring system works.");
            Console.WriteLine("Press any key to start global monitoring, then test in other applications.");
            Console.WriteLine("Press 'q' to quit.");
            Console.WriteLine();
            
            var keyboardHook = new KeyboardHookService();
            
            // Subscribe to events
            keyboardHook.KeyIntercepted += (processName, windowTitle) =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                Console.WriteLine($"[{timestamp}] 🎯 GLOBAL INPUT DETECTED:");
                Console.WriteLine($"    Process: {processName}.exe");
                if (!string.IsNullOrEmpty(windowTitle))
                    Console.WriteLine($"    Window: {windowTitle}");
                Console.WriteLine();
            };
            
            keyboardHook.HookStatusChanged += (isActive) =>
            {
                var status = isActive ? "STARTED" : "STOPPED";
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] ✅ Global monitoring {status}");
                Console.WriteLine();
            };
            
            Console.ReadKey();
            
            Console.WriteLine("🚀 Starting global keyboard monitoring...");
            Console.WriteLine("📡 Now monitoring keystrokes across ALL applications");
            Console.WriteLine("🎯 Try typing in Chrome, Notepad, File Explorer, etc.");
            Console.WriteLine("Press 'q' to stop monitoring and exit.");
            Console.WriteLine();
            
            bool success = keyboardHook.Start();
            if (!success)
            {
                Console.WriteLine("❌ Failed to start global monitoring!");
                Console.WriteLine("Ensure you're running as Administrator.");
                Console.ReadKey();
                return;
            }
            
            // Keep running until user presses 'q'
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
            } 
            while (key.KeyChar != 'q' && key.KeyChar != 'Q');
            
            Console.WriteLine("🛑 Stopping global monitoring...");
            keyboardHook.Stop();
            keyboardHook.Dispose();
            
            Console.WriteLine("✅ Test completed. Global keyboard monitoring system verified!");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
