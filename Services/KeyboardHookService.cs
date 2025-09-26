using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KeyloggerDetector.Services
{
    /// <summary>
    /// Service for implementing global keyboard monitoring using Windows API hooks
    /// Provides system-wide keystroke detection across all applications
    /// </summary>
    public class KeyboardHookService : IDisposable
    {
        #region Windows API Constants
        
        private const int WH_KEYBOARD_LL = 13; // Low-level keyboard hook
        private const int WM_KEYDOWN = 0x0100; // Key down message
        private const int WM_SYSKEYDOWN = 0x0104; // System key down message
        
        #endregion

        #region Windows API Imports
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        #endregion

        #region Delegates and Events

        /// <summary>
        /// Delegate for the low-level keyboard hook procedure
        /// </summary>
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Event fired when a key is intercepted with process information
        /// </summary>
        public event Action<string, string> KeyIntercepted;

        /// <summary>
        /// Event fired when hook status changes
        /// </summary>
        public event Action<bool> HookStatusChanged;

        #endregion

        #region Private Fields

        private LowLevelKeyboardProc _proc = null;
        private IntPtr _hookID = IntPtr.Zero;
        private bool _isHooked = false;
        private bool _disposed = false;

        #endregion

        #region Constructor

        public KeyboardHookService()
        {
            _proc = HookCallback;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts the global keyboard monitoring
        /// </summary>
        /// <returns>True if hook was successfully installed, false otherwise</returns>
        public bool Start()
        {
            try
            {
                if (_isHooked)
                {
                    Debug.WriteLine("⚠️ Hook already active");
                    return true;
                }

                _hookID = SetHook(_proc);
                if (_hookID != IntPtr.Zero)
                {
                    _isHooked = true;
                    HookStatusChanged?.Invoke(true);
                    Debug.WriteLine("✅ Global keyboard hook installed successfully");
                    return true;
                }
                else
                {
                    Debug.WriteLine("❌ Failed to install global keyboard hook");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Error starting keyboard hook: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Stops the global keyboard monitoring
        /// </summary>
        public void Stop()
        {
            try
            {
                if (_isHooked && _hookID != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(_hookID);
                    _hookID = IntPtr.Zero;
                    _isHooked = false;
                    HookStatusChanged?.Invoke(false);
                    Debug.WriteLine("✅ Global keyboard hook removed successfully");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Error stopping keyboard hook: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the current hook status
        /// </summary>
        public bool IsActive => _isHooked;

        #endregion

        #region Private Methods

        /// <summary>
        /// Sets up the low-level keyboard hook
        /// </summary>
        private IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(
                    WH_KEYBOARD_LL,
                    proc,
                    GetModuleHandle(curModule.ModuleName),
                    0);
            }
        }

        /// <summary>
        /// The hook callback procedure that intercepts keyboard events
        /// </summary>
        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                // Only process if nCode >= 0 and it's a key down event
                if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
                {
                    // Get the currently active window
                    IntPtr foregroundWindow = GetForegroundWindow();
                    
                    if (foregroundWindow != IntPtr.Zero)
                    {
                        // Get the process ID of the window that has focus
                        uint processId;
                        GetWindowThreadProcessId(foregroundWindow, out processId);
                        
                        if (processId != 0)
                        {
                            try
                            {
                                // Get the process information
                                using (Process targetProcess = Process.GetProcessById((int)processId))
                                {
                                    string processName = targetProcess.ProcessName;
                                    string windowTitle = targetProcess.MainWindowTitle;
                                    
                                    // Get the key that was pressed
                                    int vkCode = Marshal.ReadInt32(lParam);
                                    // Convert virtual key code to key name
                                    string keyName = vkCode.ToString();
                                    
                                    // Fire the event with process and key information
                                    KeyIntercepted?.Invoke(processName, windowTitle);
                                    
                                    Debug.WriteLine($"🎯 Key '{keyName}' detected in process: {processName} - {windowTitle}");
                                }
                            }
                            catch (ArgumentException)
                            {
                                // Process may have exited, ignore
                                Debug.WriteLine("⚠️ Target process exited during key detection");
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"⚠️ Error getting process info: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Error in hook callback: {ex.Message}");
            }

            // Always call the next hook in the chain
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        #endregion

        #region IDisposable Implementation

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Stop the hook when disposing
                    Stop();
                }
                _disposed = true;
            }
        }

        ~KeyboardHookService()
        {
            Dispose(false);
        }

        #endregion
    }
}
