using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace KeyloggerDetector.Services
{
    public class InputPlaygroundTracker
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int HC_ACTION = 0;
        
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private LowLevelKeyboardProc hookProc = HookCallback;
        private static IntPtr hookId = IntPtr.Zero;
        private static InputPlaygroundTracker instance;
        
        public event Action<string> InputCaptureDetected;
        
        public void StartMonitoring()
        {
            instance = this;
            hookId = SetHook(hookProc);
        }
        
        public void StopMonitoring()
        {
            UnhookWindowsHookEx(hookId);
            instance = null;
        }
        
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }
        
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= HC_ACTION && instance != null)
            {
                try
                {
                    // Get the foreground window
                    IntPtr foregroundWindow = GetForegroundWindow();
                    GetWindowThreadProcessId(foregroundWindow, out int processId);
                    
                    var process = Process.GetProcessById(processId);
                    var windowTitle = GetWindowTitle(foregroundWindow);
                    
                    // Notify which process is capturing input
                    instance.InputCaptureDetected?.Invoke($"{process.ProcessName} - {windowTitle}");
                }
                catch (Exception)
                {
                    // Ignore errors in hook callback
                }
            }
            
            return CallNextHookEx(hookId, nCode, wParam, lParam);
        }
        
        private static string GetWindowTitle(IntPtr hWnd)
        {
            const int nChars = 256;
            var buff = new System.Text.StringBuilder(nChars);
            
            if (GetWindowText(hWnd, buff, nChars) > 0)
            {
                return buff.ToString();
            }
            return "Unknown Window";
        }
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook,
            LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
            
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);
            
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetForegroundWindow();
        
        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    }
}
