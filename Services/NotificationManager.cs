using System;
using System.Threading.Tasks;

namespace KeyloggerDetector.Services
{
    public class NotificationManager
    {
        public async Task ShowThreatNotificationAsync(int threatCount)
        {
            await Task.Run(() =>
            {
                Console.WriteLine($"⚠️ KeyGuard Pro has detected {threatCount} potential threat(s) on your system.");
                Console.WriteLine("Please review the scan results and take appropriate action.");
            });
        }
        
        public async Task ShowSystemNotificationAsync(string title, string message)
        {
            await Task.Run(() =>
            {
                Console.WriteLine($"[{title}] {message}");
            });
        }
        
        public async Task ShowErrorDialogAsync(string message)
        {
            await Task.Run(() =>
            {
                Console.WriteLine($"❌ ERROR: {message}");
            });
        }
        
        public async Task ShowWarningDialogAsync(string message)
        {
            await Task.Run(() =>
            {
                Console.WriteLine($"⚠️ WARNING: {message}");
            });
        }

        public void ShowQuarantineNotification(string processName)
        {
            Console.WriteLine($"🚨 QUARANTINE: {processName} has been quarantined");
        }

        public void ShowRemovalNotification(string processName)
        {
            Console.WriteLine($"🗑️ REMOVAL: {processName} has been removed");
        }

        public void ShowThreatDetectedNotification(string processName, string threatLevel)
        {
            Console.WriteLine($"⚠️ THREAT DETECTED: {processName} - Level: {threatLevel}");
        }

        public void ShowProcessTerminatedNotification(string processName)
        {
            Console.WriteLine($"⚔️ TERMINATED: {processName} process has been terminated");
        }
    }
}
