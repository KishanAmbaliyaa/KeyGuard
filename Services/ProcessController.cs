using System;
using System.Threading.Tasks;
using System.Diagnostics;
using KeyloggerDetector.Models;
using KeyloggerDetector.Services;
using System.Linq;

namespace KeyloggerDetector.Services
{
    public class ProcessController
    {
        private readonly string[] criticalProcesses = { 
            "system", "csrss", "winlogon", "services", "lsass", "svchost", 
            "dwm", "explorer", "wininit", "smss", "winlogon" 
        };
        
        private readonly NotificationManager notificationManager;
        // private readonly DatabaseManager databaseManager;
        
        public ProcessController()
        {
            notificationManager = new NotificationManager();
            // databaseManager = new DatabaseManager();
        }
        
        public async Task<bool> TerminateProcessSafelyAsync(ProcessInfo processInfo)
        {
            if (criticalProcesses.Contains(processInfo.Name.ToLower()))
            {
                await notificationManager.ShowWarningDialogAsync(
                    $"Cannot terminate system process: {processInfo.Name}\n\n" +
                    "This is a critical Windows process that must remain running for system stability.");
                return false;
            }
            
            try
            {
                var process = Process.GetProcessById(processInfo.Id);
                
                // Try graceful termination first
                if (process.MainWindowHandle != IntPtr.Zero)
                {
                    if (!process.CloseMainWindow())
                    {
                        // Force termination after timeout
                        await Task.Delay(3000);
                        if (!process.HasExited)
                        {
                            process.Kill();
                        }
                    }
                }
                else
                {
                    // No main window, force termination
                    process.Kill();
                }
                
                // Wait for process to exit
                if (!process.WaitForExit(5000))
                {
                    await notificationManager.ShowErrorDialogAsync(
                        $"Process {processInfo.Name} did not terminate within the expected time.");
                    return false;
                }
                
                // Log the termination
                // databaseManager.LogAction("ProcessTermination", processInfo.Name, processInfo.Id,
                //     $"Threat Level: {processInfo.ThreatLevel}");
                
                await notificationManager.ShowSystemNotificationAsync(
                    "Process Terminated", 
                    $"Successfully terminated process: {processInfo.Name} (PID: {processInfo.Id})");
                
                return true;
            }
            catch (ArgumentException)
            {
                await notificationManager.ShowErrorDialogAsync(
                    $"Process {processInfo.Name} (PID: {processInfo.Id}) no longer exists.");
                return false;
            }
            catch (Exception ex)
            {
                await notificationManager.ShowErrorDialogAsync(
                    $"Failed to terminate {processInfo.Name}: {ex.Message}");
                return false;
            }
        }
        
        public bool IsSystemCriticalProcess(string processName)
        {
            return criticalProcesses.Contains(processName.ToLower());
        }
    }
}
