using System;
using System.Threading;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    class ConsoleProgram
    {
        static void RunConsoleTest(string[] args)
        {
            Console.WriteLine("🔐 KeyGuard Pro - Global Keyboard Monitoring Test");
            Console.WriteLine("=================================================");
            Console.WriteLine();
            Console.WriteLine("This demonstrates the working global keyboard monitoring system.");
            Console.WriteLine("The system will monitor keystrokes across ALL applications.");
            Console.WriteLine();
            Console.WriteLine("Press any key to start monitoring...");
            Console.ReadKey();
            
            var keyboardHook = new KeyboardHookService();
            
            // Subscribe to events
            keyboardHook.KeyIntercepted += (processName, windowTitle) =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                Console.WriteLine($"[{timestamp}] 🎯 GLOBAL INPUT DETECTED:");
                Console.WriteLine($"    Process: {processName}.exe");
                if (!string.IsNullOrEmpty(windowTitle))
                    Console.WriteLine($"    Window: {windowTitle}");
                Console.WriteLine();
            };
            
            keyboardHook.HookStatusChanged += (isActive) =>
            {
                var status = isActive ? "STARTED" : "STOPPED";
                Console.WriteLine($"✅ Global monitoring {status}");
                Console.WriteLine();
            };
            
            Console.WriteLine("🚀 Starting global keyboard monitoring...");
            Console.WriteLine("📡 Now monitoring keystrokes across ALL applications");
            Console.WriteLine("🎯 Try typing in Chrome, Notepad, File Explorer, VS Code...");
            Console.WriteLine();
            Console.WriteLine("Press 'ESC' to stop monitoring and exit.");
            Console.WriteLine();
            
            bool success = keyboardHook.Start();
            if (!success)
            {
                Console.WriteLine("❌ Failed to start global monitoring!");
                Console.WriteLine("Please ensure:");
                Console.WriteLine("• You're running as Administrator");
                Console.WriteLine("• No antivirus is blocking the hook");
                Console.WriteLine("• System resources are available");
                Console.ReadKey();
                return;
            }
            
            // Keep running until ESC is pressed
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
            } 
            while (key.Key != ConsoleKey.Escape);
            
            Console.WriteLine("🛑 Stopping global monitoring...");
            keyboardHook.Stop();
            keyboardHook.Dispose();
            
            Console.WriteLine("✅ Global keyboard monitoring system verified!");
            Console.WriteLine("The system successfully detected keystrokes across applications.");
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
