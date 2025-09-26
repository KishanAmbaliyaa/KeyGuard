using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using KeyloggerDetector.Models;
using KeyloggerDetector.Services;

namespace KeyloggerDetector
{
    public partial class MainWindow : Window
    {
        public ObservableCollection<ProcessNodeViewModel> ProcessNodes { get; set; }
        public ObservableCollection<ProcessInfo> ProcessList { get; set; }
        public ObservableCollection<string> CaptureHistory { get; set; }
        public ObservableCollection<ScanResult> ScanResults { get; set; }
        
        // New collections for enhanced playground
        public ObservableCollection<MonitoredApplication> MonitoredApps { get; set; }
        public ObservableCollection<ActivityLogEntry> ActivityLog { get; set; }
        
        private bool _isScanning = false;
        private bool _isMonitoring = false;
        private DispatcherTimer _progressTimer;
        private DispatcherTimer _processRefreshTimer;
        private DispatcherTimer _lastActivityUpdateTimer; // Timer for real-time Last Activity updates
        private DispatcherTimer _sessionTimer; // Timer for session time tracking
        private DateTime? _sessionStartTime;
        private readonly HierarchicalProcessScanner _hierarchicalScanner = new HierarchicalProcessScanner();
        private readonly KeyboardHookService _keyboardHookService = new KeyboardHookService();
        private readonly SettingsService _settingsService = new SettingsService();
        private readonly ThreatHistoryService _threatHistoryService = new ThreatHistoryService();
        private readonly ProcessScanner _processScanner = new ProcessScanner();
        private readonly ThreatDetector _threatDetector = new ThreatDetector();
        private readonly DatabaseManagerSimple _databaseManager = new DatabaseManagerSimple();
        private FileScannerService _fileScannerService;
        private List<ScanResult> _allScanResults;
        private CancellationTokenSource _scanCancellationTokenSource;
        private List<ProcessInfo> _allProcesses = new List<ProcessInfo>(); // Store full process list for filtering

        public MainWindow()
        {
            try
            {
                InitializeComponent();
                InitializeApp();
                InitializeKeyboardHook();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void InitializeApp()
        {
            ProcessNodes = new ObservableCollection<ProcessNodeViewModel>();
            ProcessList = new ObservableCollection<ProcessInfo>();
            CaptureHistory = new ObservableCollection<string>();
            ScanResults = new ObservableCollection<ScanResult>();
            _allScanResults = new List<ScanResult>();
            
            // Initialize new playground collections
            MonitoredApps = new ObservableCollection<MonitoredApplication>();
            ActivityLog = new ObservableCollection<ActivityLogEntry>();

            // Initialize file scanner service with real functionality
            var settings = _settingsService.LoadSettings();
            _fileScannerService = new FileScannerService(settings.VirusTotalApiKey);
            _fileScannerService.ProgressChanged += OnScanProgressChanged;
            _fileScannerService.FileScanned += OnFileScanned;
            _fileScannerService.ScanCompleted += OnScanCompleted;

            // TODO: Fix UI control references when implementing tree view
            // if (ProcessTreeView != null)
            //     ProcessTreeView.ItemsSource = ProcessNodes;
            // if (CaptureHistoryList != null)
            //     CaptureHistoryList.ItemsSource = CaptureHistory;

            _progressTimer = new DispatcherTimer();
            _progressTimer.Interval = TimeSpan.FromMilliseconds(100);

            _processRefreshTimer = new DispatcherTimer();
            _processRefreshTimer.Interval = TimeSpan.FromSeconds(30); // Increased from 10 to 30 seconds
            _processRefreshTimer.Tick += async (s, e) => 
            {
                // Only refresh if we're on the Process Monitor page and not already loading
                var processPage = FindName("ProcessMonitorPage") as Grid;
                if (processPage?.Visibility == Visibility.Visible && !_isLoadingProcesses)
                {
                    Debug.WriteLine("🔄 Auto-refresh timer: Starting scheduled process refresh...");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔄 Auto-refresh timer: Starting scheduled process refresh...\n");
                    await LoadProcessListAsync();
                }
                else
                {
                    Debug.WriteLine("🚫 Auto-refresh timer: Skipping refresh (page not visible or already loading)");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "🚫 Auto-refresh timer: Skipping refresh (page not visible or already loading)\n");
                }
            };

            // Initialize Last Activity update timer for real-time updates
            _lastActivityUpdateTimer = new DispatcherTimer();
            _lastActivityUpdateTimer.Interval = TimeSpan.FromSeconds(1); // Update every second
            _lastActivityUpdateTimer.Tick += LastActivityUpdateTimer_Tick;
            _lastActivityUpdateTimer.Start(); // Start immediately to run continuously
            
            // Initialize Session timer
            _sessionTimer = new DispatcherTimer();
            _sessionTimer.Interval = TimeSpan.FromSeconds(1); // Update every second
            _sessionTimer.Tick += SessionTimer_Tick;

            CaptureHistory.Add("KeyGuard Pro - Global Keyboard Monitor Ready");
            NavigateToHome();
            
            // Bind ScanResults to the DataGrid
            var scanResultsGrid = FindName("ScanResultsGrid") as DataGrid;
            if (scanResultsGrid != null)
                scanResultsGrid.ItemsSource = ScanResults;
                
            // Bind ProcessList to the ProcessDataGrid
            var processDataGrid = FindName("ProcessDataGrid") as DataGrid;
            if (processDataGrid != null)
                processDataGrid.ItemsSource = ProcessList;
                
            // Bind new playground controls
            var applicationsDataGrid = FindName("ApplicationsDataGrid") as DataGrid;
            if (applicationsDataGrid != null)
                applicationsDataGrid.ItemsSource = MonitoredApps;
                
            var activityLogList = FindName("ActivityLogList") as ListView;
            if (activityLogList != null)
                activityLogList.ItemsSource = ActivityLog;
        }

        // Event handlers for FileScannerService
        private void OnScanProgressChanged(object sender, ScanProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    var progressBar = FindName("ScanProgressBar") as ProgressBar;
                    var statusText = FindName("StatusText") as TextBlock;
                    var currentFileText = FindName("CurrentFileText") as TextBlock;
                    var progressText = FindName("ProgressText") as TextBlock;

                    if (progressBar != null)
                        progressBar.Value = e.PercentComplete;

                    if (progressText != null)
                        progressText.Text = $"{e.PercentComplete}%";

                    if (statusText != null)
                        statusText.Text = $"Scanning... {e.FilesScanned}/{e.TotalFiles} files ({e.PercentComplete}%)";

                    if (currentFileText != null && !string.IsNullOrEmpty(e.CurrentFile))
                        currentFileText.Text = $"Scanning: {Path.GetFileName(e.CurrentFile)}";
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error updating scan progress: {ex.Message}");
                }
            });
        }

        private void OnFileScanned(object sender, FileScannedEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    _allScanResults.Add(e.Result);
                    
                    // Add ALL scan results to the display, not just malicious ones
                    ScanResults.Add(e.Result);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error processing file scan result: {ex.Message}");
                }
            });
        }

        private void OnScanCompleted(object sender, ScanCompletedEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    _isScanning = false;
                    
                    var scanButton = FindName("ScanButton") as Button;
                    var cancelScanBtn = FindName("CancelScanButton") as Button;
                    var statusText = FindName("StatusText") as TextBlock;
                    var currentFileText = FindName("CurrentFileText") as TextBlock;
                    var progressBar = FindName("ScanProgressBar") as ProgressBar;

                    if (scanButton != null)
                        scanButton.Content = "🔍 START SCAN";
                    
                    if (cancelScanBtn != null)
                        cancelScanBtn.Visibility = Visibility.Collapsed;

                    if (progressBar != null)
                        progressBar.Value = 100;

                    if (e.WasCancelled)
                    {
                        if (statusText != null)
                            statusText.Text = "Scan cancelled";
                        if (currentFileText != null)
                            currentFileText.Text = "";
                    }
                    else
                    {
                        var threatsFound = e.Results.Count(r => r.IsMalicious);
                        if (statusText != null)
                            statusText.Text = $"Scan completed: {e.TotalFiles} files scanned, {threatsFound} threats found";
                        if (currentFileText != null)
                            currentFileText.Text = "Scan completed";

                        // Update the summary section instead of showing popup
                        UpdateScanSummary(e.Results, e.Duration);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error handling scan completion: {ex.Message}");
                }
            });
        }

        private void UpdateScanSummary(List<ScanResult> results, TimeSpan duration)
        {
            try
            {
                // Show the summary grid
                var summaryGrid = FindName("ScanSummaryGrid") as Grid;
                if (summaryGrid != null)
                    summaryGrid.Visibility = Visibility.Visible;

                // Calculate statistics
                var totalFiles = results.Count;
                var cleanFiles = results.Count(r => !r.IsMalicious && r.Status != "Error");
                var maliciousFiles = results.Count(r => r.IsMalicious);
                var suspiciousFiles = results.Count(r => r.Status.Contains("Suspicious") && !r.IsMalicious);
                var errorFiles = results.Count(r => r.Status == "Error");

                // Update summary text blocks
                var totalFilesText = FindName("TotalFilesText") as TextBlock;
                var cleanFilesText = FindName("CleanFilesText") as TextBlock;
                var suspiciousFilesText = FindName("SuspiciousFilesText") as TextBlock;
                var maliciousFilesText = FindName("MaliciousFilesText") as TextBlock;
                var scanDurationText = FindName("ScanDurationText") as TextBlock;

                if (totalFilesText != null)
                    totalFilesText.Text = totalFiles.ToString();
                
                if (cleanFilesText != null)
                    cleanFilesText.Text = cleanFiles.ToString();
                
                if (suspiciousFilesText != null)
                    suspiciousFilesText.Text = suspiciousFiles.ToString();
                
                if (maliciousFilesText != null)
                    maliciousFilesText.Text = maliciousFiles.ToString();
                
                if (scanDurationText != null)
                    scanDurationText.Text = $"{duration.TotalSeconds:F1}s";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating scan summary: {ex.Message}");
            }
        }

        private void InitializeKeyboardHook()
        {
            _keyboardHookService.KeyIntercepted += OnKeyIntercepted;
            _keyboardHookService.HookStatusChanged += OnHookStatusChanged;
        }

        private void OnKeyIntercepted(string processName, string windowTitle)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    // Find or create monitored application entry
                    var monitoredApp = MonitoredApps.FirstOrDefault(app => app.ApplicationName == processName);
                    if (monitoredApp == null)
                    {
                        // Get process information
                        try
                        {
                            var processes = Process.GetProcessesByName(processName);
                            if (processes.Length > 0)
                            {
                                var process = processes[0];
                                monitoredApp = new MonitoredApplication
                                {
                                    ApplicationName = processName,
                                    ProcessId = process.Id,
                                    FilePath = GetProcessFilePath(process),
                                    IsSystemApp = IsSystemProcess(processName)
                                };
                                MonitoredApps.Add(monitoredApp);
                                
                                // Add initial detection log entry
                                var initialLogEntry = new ActivityLogEntry
                                {
                                    ApplicationName = processName,
                                    ProcessId = process.Id,
                                    EventType = "Application Detected",
                                    Details = $"New application detected with keyboard input: {windowTitle}",
                                    Severity = "INFO"
                                };
                                ActivityLog.Insert(0, initialLogEntry);
                            }
                        }
                        catch (Exception ex)
                        {
                            // If we can't get process info, create a basic entry
                            monitoredApp = new MonitoredApplication
                            {
                                ApplicationName = processName,
                                ProcessId = 0,
                                FilePath = "Unknown",
                                IsSystemApp = IsSystemProcess(processName)
                            };
                            MonitoredApps.Add(monitoredApp);
                        }
                    }
                    
                    // Update monitored app
                    if (monitoredApp != null)
                    {
                        monitoredApp.IncrementInputCount();
                        
                        // Add detailed activity log entry with enhanced messages
                        var logEntry = CreateEnhancedActivityLogEntry(processName, monitoredApp.ProcessId, windowTitle, monitoredApp.InputCount);
                        ActivityLog.Insert(0, logEntry);
                        
                        // Keep log manageable (max 500 entries)
                        while (ActivityLog.Count > 500)
                            ActivityLog.RemoveAt(ActivityLog.Count - 1);
                    }
                    
                    // Update UI statistics
                    UpdatePlaygroundStatistics();
                    
                    // Auto-scroll log if enabled
                    var autoScrollLog = FindName("AutoScrollLog") as CheckBox;
                    if (autoScrollLog?.IsChecked == true)
                    {
                        var activityLogList = FindName("ActivityLogList") as ListView;
                        if (activityLogList != null && ActivityLog.Count > 0)
                        {
                            activityLogList.ScrollIntoView(ActivityLog[0]);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Add error log entry
                    var errorLogEntry = new ActivityLogEntry
                    {
                        ApplicationName = "System",
                        ProcessId = 0,
                        EventType = "Error",
                        Details = $"Error processing key intercept: {ex.Message}",
                        Severity = "ERROR"
                    };
                    ActivityLog.Insert(0, errorLogEntry);
                }
            }));
        }

        private void OnHookStatusChanged(bool isActive)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    // Update monitoring status
                    var monitoringStatus = FindName("MonitoringStatus") as TextBlock;
                    var monitoringDetails = FindName("MonitoringDetails") as TextBlock;
                    var monitoringStatusIndicator = FindName("MonitoringStatusIndicator") as TextBlock;
                    
                    if (isActive)
                    {
                        if (monitoringStatus != null)
                        {
                            monitoringStatus.Text = "Global keyboard monitoring ACTIVE";
                            monitoringStatus.Foreground = new SolidColorBrush(Colors.LimeGreen);
                        }
                        if (monitoringDetails != null)
                        {
                            monitoringDetails.Text = "Capturing keyboard input across all applications in real-time";
                        }
                        if (monitoringStatusIndicator != null)
                        {
                            monitoringStatusIndicator.Text = "Active";
                            monitoringStatusIndicator.Foreground = new SolidColorBrush(Colors.LimeGreen);
                        }
                    }
                    else
                    {
                        if (monitoringStatus != null)
                        {
                            monitoringStatus.Text = "Global keyboard monitoring disabled";
                            monitoringStatus.Foreground = new SolidColorBrush(Colors.Gray);
                        }
                        if (monitoringDetails != null)
                        {
                            monitoringDetails.Text = "Click START to begin capturing keyboard input across all applications";
                        }
                        if (monitoringStatusIndicator != null)
                        {
                            monitoringStatusIndicator.Text = "Stopped";
                            monitoringStatusIndicator.Foreground = new SolidColorBrush(Colors.Red);
                        }
                    }
                    
                    // Add status log entry
                    var statusLogEntry = new ActivityLogEntry
                    {
                        ApplicationName = "KeyGuard Pro",
                        ProcessId = Process.GetCurrentProcess().Id,
                        EventType = "Monitoring Status",
                        Details = isActive ? "Global keyboard monitoring started" : "Global keyboard monitoring stopped",
                        Severity = "INFO"
                    };
                    ActivityLog.Insert(0, statusLogEntry);
                    
                    // Update statistics
                    UpdatePlaygroundStatistics();
                }
                catch (Exception ex)
                {
                    var errorLogEntry = new ActivityLogEntry
                    {
                        ApplicationName = "System",
                        ProcessId = 0,
                        EventType = "Error",
                        Details = $"Error updating hook status: {ex.Message}",
                        Severity = "ERROR"
                    };
                    ActivityLog.Insert(0, errorLogEntry);
                }
            }));
        }

        private void LastActivityUpdateTimer_Tick(object sender, EventArgs e)
        {
            // Update LastActivity for all monitored apps to trigger real-time display
            foreach (var app in MonitoredApps)
            {
                app.UpdateLastActivity();
            }
        }

        private void SessionTimer_Tick(object sender, EventArgs e)
        {
            // Update session time display
            var sessionTimeText = FindName("SessionTimeText") as TextBlock;
            if (sessionTimeText != null && _sessionStartTime.HasValue)
            {
                var sessionDuration = DateTime.Now - _sessionStartTime.Value;
                sessionTimeText.Text = sessionDuration.ToString(@"hh\:mm\:ss");
            }
        }

        private ActivityLogEntry CreateEnhancedActivityLogEntry(string processName, int processId, string windowTitle, int inputCount)
        {
            var random = new Random();
            string eventType;
            string details;

            // Create varied event types and messages based on application and context
            var eventVariations = new[]
            {
                "Keyboard Activity",
                "Input Detection", 
                "Keystroke Event",
                "User Interaction",
                "Text Input"
            };

            var detailVariations = new[]
            {
                $"User typing in {processName}",
                $"Active input session detected",
                $"Keystroke #{inputCount} recorded",
                $"User interaction captured",
                $"Text entry in progress",
                $"Application receiving input",
                $"User engagement detected"
            };

            eventType = eventVariations[random.Next(eventVariations.Length)];
            
            if (!string.IsNullOrEmpty(windowTitle))
            {
                var windowVariations = new[]
                {
                    $"Typing in window: '{windowTitle}'",
                    $"Active in window: {windowTitle}",
                    $"Input captured from: {windowTitle}",
                    $"User typing in: {windowTitle}",
                    $"Window activity: {windowTitle}"
                };
                details = windowVariations[random.Next(windowVariations.Length)];
            }
            else
            {
                details = detailVariations[random.Next(detailVariations.Length)];
            }

            return new ActivityLogEntry
            {
                ApplicationName = processName,
                ProcessId = processId,
                EventType = eventType,
                Details = details,
                Severity = "INFO"
            };
        }

        private async Task LoadProcessHierarchyAsync()
        {
            try
            {
                var progress = new Progress<string>(message =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        if (ProcessStatusText != null)
                            ProcessStatusText.Text = message;
                    });
                });

                var processNodes = await _hierarchicalScanner.ScanProcessHierarchyAsync(progress);
                
                await Dispatcher.InvokeAsync(() =>
                {
                    ProcessNodes.Clear();
                    foreach (var node in processNodes)
                        ProcessNodes.Add(node);
                    
                    var totalProcesses = CountAllProcessNodes(processNodes);
                    var suspiciousCount = CountSuspiciousProcessNodes(processNodes);
                    
                    if (ProcessStatusText != null)
                        ProcessStatusText.Text = $"Hierarchical view: {totalProcesses} processes ({suspiciousCount} suspicious)";
                    
                    if (ProcessCountLabel != null)
                        ProcessCountLabel.Text = $"{totalProcesses} processes";
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LoadProcessHierarchy error: {ex}");
            }
        }

        private bool _isLoadingProcesses = false;
        private bool _initialProcessLoadCompleted = false;
        
        private async Task LoadProcessListAsync()
        {
            if (_isLoadingProcesses)
            {
                Debug.WriteLine("🚫 LoadProcessListAsync: Already loading, skipping...");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", "🚫 LoadProcessListAsync: Already loading, skipping...\n");
                return;
            }
            
            _isLoadingProcesses = true;
            
            try
            {
                Debug.WriteLine("🔄 LoadProcessListAsync: Starting process scan...");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔄 LoadProcessListAsync: Starting process scan...\n");
                
                var progress = new Progress<string>(message =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        var processStatusText = FindName("ProcessStatusText") as TextBlock;
                        if (processStatusText != null)
                        {
                            processStatusText.Text = message;
                            Debug.WriteLine($"📊 Status update: {message}");
                            System.IO.File.AppendAllText(@"C:\temp\debug.log", $"📊 Status update: {message}\n");
                        }
                        else
                        {
                            Debug.WriteLine("⚠️ ProcessStatusText control not found!");
                            System.IO.File.AppendAllText(@"C:\temp\debug.log", "⚠️ ProcessStatusText control not found!\n");
                        }
                    });
                });

                Debug.WriteLine("🔍 Calling ProcessScanner.GetAllProcessesAsync()...");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔍 Calling ProcessScanner.GetAllProcessesAsync()...\n");
                var processes = await _processScanner.GetAllProcessesAsync();
                Debug.WriteLine($"✅ Process scan completed: {processes.Count} processes found");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", $"✅ Process scan completed: {processes.Count} processes found\n");
                
                await Dispatcher.InvokeAsync(() =>
                {
                    Debug.WriteLine("🔄 Updating UI with process data...");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔄 Updating UI with process data...\n");
                    
                    try
                    {
                        ProcessList.Clear();
                        
                        // Store all processes for filtering
                        _allProcesses = processes.ToList();
                        Debug.WriteLine($"📦 Stored {_allProcesses.Count} processes for filtering");
                        
                        // Display all processes - removed 50 limit per user request
                        Debug.WriteLine($"� Adding all {processes.Count} processes to display");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", $"� Adding all {processes.Count} processes to display\n");
                        
                        foreach (var process in processes)
                            ProcessList.Add(process);
                        
                        Debug.WriteLine($"📋 ProcessList updated: {ProcessList.Count} items");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", $"📋 ProcessList updated: {ProcessList.Count} items\n");
                        
                        var processStatusText = FindName("ProcessStatusText") as TextBlock;
                        if (processStatusText != null)
                            processStatusText.Text = $"{ProcessList.Count} processes";
                        
                        var processCountLabel = FindName("ProcessCountLabel") as TextBlock;
                        if (processCountLabel != null)
                            processCountLabel.Text = $"{ProcessList.Count} processes";
                            
                        // Verify DataGrid binding with limited data
                        var processDataGrid = FindName("ProcessDataGrid") as DataGrid;
                        if (processDataGrid != null)
                        {
                            Debug.WriteLine($"🔗 DataGrid ItemsSource: {processDataGrid.ItemsSource != null}");
                            Debug.WriteLine($"🔗 DataGrid Items.Count: {processDataGrid.Items.Count}");
                            System.IO.File.AppendAllText(@"C:\temp\debug.log", $"🔗 DataGrid ItemsSource: {processDataGrid.ItemsSource != null}\n");
                            System.IO.File.AppendAllText(@"C:\temp\debug.log", $"🔗 DataGrid Items.Count: {processDataGrid.Items.Count}\n");
                        }
                        else
                        {
                            Debug.WriteLine("⚠️ ProcessDataGrid control not found!");
                            System.IO.File.AppendAllText(@"C:\temp\debug.log", "⚠️ ProcessDataGrid control not found!\n");
                        }
                        
                        Debug.WriteLine("✅ UI update completed successfully");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", "✅ UI update completed successfully\n");
                    }
                    catch (Exception uiEx)
                    {
                        Debug.WriteLine($"❌ UI update error: {uiEx.Message}");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ UI update error: {uiEx.Message}\n");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ UI stack trace: {uiEx.StackTrace}\n");
                        throw; // Re-throw to be caught by outer handler
                    }
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ LoadProcessList error: {ex.Message}");
                Debug.WriteLine($"❌ Stack trace: {ex.StackTrace}");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ LoadProcessList error: {ex.Message}\n");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ Stack trace: {ex.StackTrace}\n");
                
                Dispatcher.Invoke(() =>
                {
                    var processStatusText = FindName("ProcessStatusText") as TextBlock;
                    if (processStatusText != null)
                        processStatusText.Text = $"Error loading processes: {ex.Message}";
                });
            }
            finally
            {
                _isLoadingProcesses = false;
                if (!_initialProcessLoadCompleted)
                {
                    _initialProcessLoadCompleted = true;
                    Debug.WriteLine("✅ Initial process load completed! Auto-refresh will now start if enabled.");
                    // Start auto-refresh timer if enabled and we just completed the initial load
                    StartAutoRefreshIfEnabled();
                }
                Debug.WriteLine("🔓 LoadProcessListAsync: Loading flag cleared");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔓 LoadProcessListAsync: Loading flag cleared\n");
            }
        }

        private void StartAutoRefreshIfEnabled()
        {
            try
            {
                var autoRefreshCheckBox = FindName("AutoRefreshCheckBox") as CheckBox;
                if (autoRefreshCheckBox?.IsChecked == true && _initialProcessLoadCompleted)
                {
                    // Create lightweight auto-refresh timer
                    if (_processRefreshTimer == null)
                    {
                        _processRefreshTimer = new DispatcherTimer();
                        _processRefreshTimer.Tick += async (s, args) => 
                        {
                            if (_initialProcessLoadCompleted && !_isLoadingProcesses)
                            {
                                Debug.WriteLine("🔄 Smart auto-refresh: Starting lightweight process update...");
                                await PerformLightweightProcessUpdate();
                            }
                        };
                    }
                    
                    // Use 5-second interval for lightweight updates
                    _processRefreshTimer.Interval = TimeSpan.FromSeconds(5);
                    _processRefreshTimer.Start();
                    Debug.WriteLine("✅ Smart auto-refresh enabled: 5-second lightweight updates");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Error starting auto-refresh: {ex.Message}");
            }
        }

        private async Task PerformLightweightProcessUpdate()
        {
            try
            {
                // Quick, lightweight process update without full re-scan
                var currentProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                var displayedProcesses = ProcessList.Select(p => p.Id).ToHashSet();
                
                // Check for new processes
                var newProcessIds = currentProcesses.Except(displayedProcesses).ToList();
                // Check for terminated processes
                var terminatedProcessIds = displayedProcesses.Except(currentProcesses).ToList();
                
                if (newProcessIds.Any() || terminatedProcessIds.Any())
                {
                    Debug.WriteLine($"🔄 Process changes detected: +{newProcessIds.Count} new, -{terminatedProcessIds.Count} terminated");
                    
                    // Remove terminated processes
                    await Dispatcher.InvokeAsync(() =>
                    {
                        for (int i = ProcessList.Count - 1; i >= 0; i--)
                        {
                            if (terminatedProcessIds.Contains(ProcessList[i].Id))
                            {
                                ProcessList.RemoveAt(i);
                            }
                        }
                    });
                    
                    // Add new processes (lightweight - only basic info)
                    if (newProcessIds.Count <= 10) // Limit to prevent performance issues
                    {
                        foreach (var pid in newProcessIds.Take(10))
                        {
                            try
                            {
                                var process = Process.GetProcessById(pid);
                                var processInfo = new ProcessInfo
                                {
                                    Name = process.ProcessName,
                                    Id = process.Id,
                                    Path = GetProcessPath(process) ?? "Unknown",
                                    ThreatLevel = "Safe",
                                    ProcessType = GetProcessTypeBasic(GetProcessPath(process), process.ProcessName),
                                    Description = "New Process",
                                    MemoryUsage = process.WorkingSet64,
                                    CpuUsage = 0
                                };
                                
                                await Dispatcher.InvokeAsync(() => ProcessList.Add(processInfo));
                            }
                            catch
                            {
                                // Skip processes we can't access
                            }
                        }
                    }
                    
                    // Apply current filters to the updated list
                    ApplyProcessFilters();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Lightweight update error: {ex.Message}");
            }
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private string GetProcessTypeBasic(string processPath, string processName)
        {
            try
            {
                if (string.IsNullOrEmpty(processPath))
                    return "Unknown";

                var pathLower = processPath.ToLower();
                
                if (pathLower.StartsWith(@"c:\windows\"))
                    return "System";
                if (pathLower.StartsWith(@"c:\program files\") || pathLower.StartsWith(@"c:\program files (x86)\"))
                    return "User";
                    
                return "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        private int CountAllProcessNodes(System.Collections.Generic.IEnumerable<ProcessNodeViewModel> nodes)
        {
            int count = 0;
            foreach (var node in nodes)
            {
                count++;
                count += CountAllProcessNodes(node.Children);
            }
            return count;
        }

        private int CountSuspiciousProcessNodes(System.Collections.Generic.IEnumerable<ProcessNodeViewModel> nodes)
        {
            int count = 0;
            foreach (var node in nodes)
            {
                if (node.ProcessDetails.IsSuspicious)
                    count++;
                count += CountSuspiciousProcessNodes(node.Children);
            }
            return count;
        }

        // Navigation system using FindName for dynamic control access
        private void NavigateToHome()
        {
            HideAllPages();
            var homePage = FindName("HomePage") as Grid;
            if (homePage != null) homePage.Visibility = Visibility.Visible;
            _processRefreshTimer?.Stop();
        }

        private void NavigateToScanner()
        {
            HideAllPages();
            var scannerPage = FindName("ScannerPage") as Grid;
            if (scannerPage != null) scannerPage.Visibility = Visibility.Visible;
            _processRefreshTimer?.Stop();
        }

        private void NavigateToProcesses()
        {
            try
            {
                Debug.WriteLine("🔄 NavigateToProcesses: Starting navigation...");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔄 NavigateToProcesses: Starting navigation...\n");
                
                HideAllPages();
                var processPage = FindName("ProcessMonitorPage") as Grid;
                if (processPage != null)
                {
                    Debug.WriteLine("✅ ProcessMonitorPage found, making visible...");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "✅ ProcessMonitorPage found, making visible...\n");
                    processPage.Visibility = Visibility.Visible;
                    
                    // Set up DataGrid binding if not already set
                    var processDataGrid = FindName("ProcessDataGrid") as DataGrid;
                    if (processDataGrid != null && processDataGrid.ItemsSource == null)
                    {
                        Debug.WriteLine("🔗 Setting up ProcessDataGrid binding...");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", "🔗 Setting up ProcessDataGrid binding...\n");
                        processDataGrid.ItemsSource = ProcessList;
                    }
                    else if (processDataGrid != null)
                    {
                        Debug.WriteLine($"🔗 ProcessDataGrid already bound. Items: {processDataGrid.Items.Count}");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", $"🔗 ProcessDataGrid already bound. Items: {processDataGrid.Items.Count}\n");
                    }
                    else
                    {
                        Debug.WriteLine("⚠️ ProcessDataGrid not found!");
                        System.IO.File.AppendAllText(@"C:\temp\debug.log", "⚠️ ProcessDataGrid not found!\n");
                    }
                    
                    Debug.WriteLine("🚀 Starting initial process load...");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "🚀 Starting initial process load...\n");
                    _ = LoadProcessListAsync();
                    
                    // DISABLE auto-refresh timer for now to prevent crashes
                    Debug.WriteLine("⚠️ Auto-refresh timer DISABLED to prevent crashes");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "⚠️ Auto-refresh timer DISABLED to prevent crashes\n");
                    // _processRefreshTimer?.Start();
                }
                else
                {
                    Debug.WriteLine("❌ ProcessMonitorPage not found!");
                    System.IO.File.AppendAllText(@"C:\temp\debug.log", "❌ ProcessMonitorPage not found!\n");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ NavigateToProcesses error: {ex.Message}");
                Debug.WriteLine($"❌ Stack trace: {ex.StackTrace}");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ NavigateToProcesses error: {ex.Message}\n");
                System.IO.File.AppendAllText(@"C:\temp\debug.log", $"❌ Stack trace: {ex.StackTrace}\n");
            }
        }

        private void NavigateToPlayground()
        {
            HideAllPages();
            var playgroundPage = FindName("PlaygroundPage") as Grid;
            if (playgroundPage != null) playgroundPage.Visibility = Visibility.Visible;
            _processRefreshTimer?.Stop();
        }

        private void HideAllPages()
        {
            var homePage = FindName("HomePage") as Grid;
            var scannerPage = FindName("ScannerPage") as Grid;
            var processPage = FindName("ProcessMonitorPage") as Grid;
            var playgroundPage = FindName("PlaygroundPage") as Grid;
            
            if (homePage != null) homePage.Visibility = Visibility.Collapsed;
            if (scannerPage != null) scannerPage.Visibility = Visibility.Collapsed;
            if (processPage != null) processPage.Visibility = Visibility.Collapsed;
            if (playgroundPage != null) playgroundPage.Visibility = Visibility.Collapsed;
        }

        // Event Handlers
        private void NavigateToHome(object sender, RoutedEventArgs e) => NavigateToHome();
        private void NavigateToScanner(object sender, RoutedEventArgs e) => NavigateToScanner();
        private void NavigateToProcesses(object sender, RoutedEventArgs e) => NavigateToProcesses();
        private void NavigateToPlayground(object sender, RoutedEventArgs e) => NavigateToPlayground();

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            try { this.DragMove(); } catch { }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void RefreshProcesses_Click(object sender, RoutedEventArgs e)
        {
            _ = LoadProcessHierarchyAsync();
        }

        private void ProcessSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Trigger real-time filtering as user types with minimal delay
            Debug.WriteLine("🔍 Search box text changed");
            PerformFastSearch();
        }

        private void PerformFastSearch()
        {
            try
            {
                // Try to find the search box
                var searchBox = FindName("ProcessSearchBox") as TextBox;
                
                if (searchBox == null)
                {
                    Debug.WriteLine("❌ Search box not found");
                    return;
                }

                var searchTerm = searchBox.Text?.Trim() ?? "";
                Debug.WriteLine($"🔍 Search term: '{searchTerm}'");
                
                // Clear search if empty or placeholder text
                if (string.IsNullOrEmpty(searchTerm) || searchTerm == "Search processes...")
                {
                    Debug.WriteLine("🔍 Clearing search - showing all processes");
                    // Show all cached processes
                    Dispatcher.InvokeAsync(() =>
                    {
                        ProcessList.Clear();
                        foreach (var process in _allProcesses)
                        {
                            ProcessList.Add(process);
                        }
                        Debug.WriteLine($"🔍 Restored {ProcessList.Count} processes");
                    });
                    return;
                }

                // Apply search filter
                var searchTermLower = searchTerm.ToLowerInvariant();
                var filteredProcesses = _allProcesses.Where(p => 
                    p.Name.ToLowerInvariant().Contains(searchTermLower) ||
                    p.Id.ToString().Contains(searchTermLower) ||
                    (!string.IsNullOrEmpty(p.Path) && p.Path.ToLowerInvariant().Contains(searchTermLower)) ||
                    (!string.IsNullOrEmpty(p.Description) && p.Description.ToLowerInvariant().Contains(searchTermLower))
                ).ToList();

                Debug.WriteLine($"🔍 Search '{searchTerm}' found {filteredProcesses.Count} matches out of {_allProcesses.Count} total");

                // Update UI
                Dispatcher.InvokeAsync(() =>
                {
                    ProcessList.Clear();
                    foreach (var process in filteredProcesses)
                    {
                        ProcessList.Add(process);
                    }

                    var processStatusText = FindName("ProcessStatusText") as TextBlock;
                    if (processStatusText != null)
                        processStatusText.Text = $"{ProcessList.Count} processes (filtered)";
                        
                    Debug.WriteLine($"🔍 Updated UI with {ProcessList.Count} filtered processes");
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Search error: {ex.Message}");
            }
        }

        private void TerminateProcess_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessInfo processInfo = null;
                
                // Handle both ProcessInfo and ProcessNodeViewModel
                if (sender is Button button && button.CommandParameter is ProcessInfo directProcess)
                {
                    processInfo = directProcess;
                }
                else if (sender is Button button2 && button2.CommandParameter is ProcessNodeViewModel nodeViewModel)
                {
                    processInfo = nodeViewModel.ProcessDetails;
                }

                if (processInfo != null)
                {
                    var result = MessageBox.Show(
                        $"Are you sure you want to terminate '{processInfo.Name}' (PID: {processInfo.Id})?\n\n" +
                        $"⚠️ Warning: Terminating system processes may cause system instability.",
                        "Confirm Process Termination",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (result == MessageBoxResult.Yes)
                    {
                        try
                        {
                            var process = Process.GetProcessById(processInfo.Id);
                            process.Kill();
                            
                            MessageBox.Show($"Process '{processInfo.Name}' (PID: {processInfo.Id}) terminated successfully.", 
                                          "Process Terminated", MessageBoxButton.OK, MessageBoxImage.Information);
                            
                            Debug.WriteLine($"⚠️ Terminated process: {processInfo.Name} (PID: {processInfo.Id})");
                            
                            // Refresh the process list
                            _ = LoadProcessListAsync();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Failed to terminate process '{processInfo.Name}':\n\n{ex.Message}", 
                                          "Termination Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            Debug.WriteLine($"❌ Failed to terminate process {processInfo.Name}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Please select a process to terminate.", "No Selection", 
                                  MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error in process termination: {ex.Message}", "Error", 
                              MessageBoxButton.OK, MessageBoxImage.Error);
                Debug.WriteLine($"❌ Error in TerminateProcess_Click: {ex.Message}");
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedFolderText = FindName("SelectedFolderText") as TextBlock;
                if (selectedFolderText == null || selectedFolderText.Text == "No folder selected")
                {
                    MessageBox.Show("Please select a folder to scan first.", "No Folder Selected", 
                                   MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (_isScanning)
                {
                    // Cancel current scan
                    _scanCancellationTokenSource?.Cancel();
                    _isScanning = false;
                    
                    var scanButton = FindName("ScanButton") as Button;
                    if (scanButton != null)
                        scanButton.Content = "🔍 START SCAN";
                    
                    return;
                }

                _isScanning = true;
                _scanCancellationTokenSource = new CancellationTokenSource();
                
                var scanBtn = FindName("ScanButton") as Button;
                var cancelScanBtn = FindName("CancelScanButton") as Button;
                
                if (scanBtn != null)
                    scanBtn.Content = "⏹️ STOP SCAN";
                
                if (cancelScanBtn != null)
                    cancelScanBtn.Visibility = Visibility.Visible;

                // Reset progress display
                var progressText = FindName("ProgressText") as TextBlock;
                if (progressText != null)
                    progressText.Text = "0%";

                // Clear previous results
                ScanResults.Clear();
                _allScanResults.Clear();

                // Hide summary section
                var summaryGrid = FindName("ScanSummaryGrid") as Grid;
                if (summaryGrid != null)
                    summaryGrid.Visibility = Visibility.Collapsed;

                // Start the REAL scan using FileScannerService
                var results = await _fileScannerService.ScanFolderAsync(
                    selectedFolderText.Text, 
                    includeSubfolders: true, 
                    useVirusTotal: true, 
                    _scanCancellationTokenSource.Token);

                // Scan completed successfully
                _isScanning = false;
                
                if (scanBtn != null)
                    scanBtn.Content = "🔍 START SCAN";
                
                if (cancelScanBtn != null)
                    cancelScanBtn.Visibility = Visibility.Collapsed;
            }
            catch (OperationCanceledException)
            {
                // Scan was cancelled
                _isScanning = false;
                var statusText = FindName("StatusText") as TextBlock;
                if (statusText != null)
                    statusText.Text = "Scan cancelled";
            }
            catch (Exception ex)
            {
                _isScanning = false;
                MessageBox.Show($"Error during scan: {ex.Message}", "Scan Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
                
                var scanBtn = FindName("ScanButton") as Button;
                if (scanBtn != null)
                    scanBtn.Content = "🔍 START SCAN";
            }
        }

        private void MonitoringToggle_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_isMonitoring)
                {
                    _keyboardHookService.Stop();
                    _isMonitoring = false;
                    
                    // Stop only session timer, keep last activity timer running
                    _sessionTimer?.Stop();
                    
                    var monitoringToggle = FindName("MonitoringToggle") as Button;
                    if (monitoringToggle != null)
                        monitoringToggle.Content = "🎯 START MONITORING";
                }
                else
                {
                    bool success = _keyboardHookService.Start();
                    if (success)
                    {
                        _isMonitoring = true;
                        
                        // Start session timer and set session start time (last activity timer runs continuously)
                        _sessionStartTime = DateTime.Now;
                        _sessionTimer?.Start();
                        
                        var monitoringToggle = FindName("MonitoringToggle") as Button;
                        if (monitoringToggle != null)
                            monitoringToggle.Content = "⏹️ STOP MONITORING";
                    }
                    else
                    {
                        MessageBox.Show(
                            "Failed to start global keyboard monitoring. Please ensure the application is running as Administrator.",
                            "Global Monitoring Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error with global monitoring: {ex.Message}", "Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }        private void PlaygroundTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_isMonitoring && sender is TextBox textBox)
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                CaptureHistory.Add($"[{timestamp}] Local input detected: {textBox.Text.Length} characters");
            }
        }

        // File Scanner Functionality
        private void FilterResults_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Button button && button.Tag is string filterType)
                {
                    ApplyFilter(filterType);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error applying filter: {ex.Message}", "Filter Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ApplyFilter(string filterType)
        {
            try
            {
                if (_allScanResults == null) return;

                IEnumerable<ScanResult> filteredResults = filterType switch
                {
                    "All" => _allScanResults,
                    "Clean" => _allScanResults.Where(r => !r.IsMalicious && r.Status != "Error"),
                    "Suspicious" => _allScanResults.Where(r => r.Status.Contains("Suspicious") && !r.IsMalicious),
                    "Malicious" => _allScanResults.Where(r => r.IsMalicious),
                    "Unknown" => _allScanResults.Where(r => r.Status == "Unknown" || r.Status == "Error"),
                    _ => _allScanResults
                };

                ScanResults.Clear();
                foreach (var result in filteredResults)
                {
                    ScanResults.Add(result);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error applying filter: {ex.Message}");
            }
        }

        private void DeleteSelectedFiles_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // var selectedItems = ScanResultsGrid.SelectedItems.Cast<ScanResult>().ToList();
                var selectedItems = new List<ScanResult>(); // TODO: Fix grid reference
                if (selectedItems.Count == 0)
                {
                    MessageBox.Show("Please select files to delete.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var result = MessageBox.Show(
                    $"Are you sure you want to delete {selectedItems.Count} selected file(s)?\n\nThis action cannot be undone!",
                    "Confirm Deletion",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);

                if (result == MessageBoxResult.Yes)
                {
                    int deletedCount = 0;
                    foreach (var item in selectedItems)
                    {
                        try
                        {
                            if (File.Exists(item.FilePath))
                            {
                                File.Delete(item.FilePath);
                                deletedCount++;
                            }
                        }
                        catch { }
                    }

                    // Remove deleted files from collections
                    var deletedPaths = selectedItems.Where(item => !File.Exists(item.FilePath)).Select(item => item.FilePath).ToHashSet();
                    
                    for (int i = ScanResults.Count - 1; i >= 0; i--)
                    {
                        if (deletedPaths.Contains(ScanResults[i].FilePath))
                        {
                            ScanResults.RemoveAt(i);
                        }
                    }

                    if (_allScanResults != null)
                    {
                        _allScanResults = _allScanResults.Where(r => !deletedPaths.Contains(r.FilePath)).ToList();
                    }

                    MessageBox.Show($"Successfully deleted {deletedCount} file(s).", "Deletion Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during file deletion: {ex.Message}", "Deletion Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyPath_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // var selectedItems = ScanResultsGrid.SelectedItems.Cast<ScanResult>().ToList();
                var selectedItems = new List<ScanResult>(); // TODO: Fix grid reference
                if (selectedItems.Count == 0) return;

                if (selectedItems.Count == 1)
                {
                    Clipboard.SetText(selectedItems[0].FilePath);
                }
                else
                {
                    var paths = string.Join(Environment.NewLine, selectedItems.Select(item => item.FilePath));
                    Clipboard.SetText(paths);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying path: {ex.Message}", "Copy Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OpenFileLocation_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // var selectedItems = ScanResultsGrid.SelectedItems.Cast<ScanResult>().ToList();
                var selectedItems = new List<ScanResult>(); // TODO: Fix grid reference
                if (selectedItems.Count == 0) return;

                foreach (var item in selectedItems.Take(5))
                {
                    if (File.Exists(item.FilePath))
                    {
                        Process.Start("explorer.exe", $"/select,\"{item.FilePath}\"");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening file location: {ex.Message}", "Open Location Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // File Scanner event handlers
        private void SelectFolderButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var folderDialog = new System.Windows.Forms.FolderBrowserDialog();
                folderDialog.Description = "Select folder to scan for malware";
                folderDialog.ShowNewFolderButton = false;
                
                if (folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    var selectedFolderText = FindName("SelectedFolderText") as TextBlock;
                    if (selectedFolderText != null)
                    {
                        selectedFolderText.Text = folderDialog.SelectedPath;
                    }
                    
                    var scanButton = FindName("ScanButton") as Button;
                    if (scanButton != null)
                    {
                        scanButton.IsEnabled = true;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error selecting folder: {ex.Message}", "Folder Selection Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void CancelScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _isScanning = false;
                
                var scanButton = FindName("ScanButton") as Button;
                var cancelScanButton = FindName("CancelScanButton") as Button;
                
                if (scanButton != null)
                {
                    scanButton.Content = "🔍 START SCAN";
                    scanButton.IsEnabled = true;
                }
                
                if (cancelScanButton != null)
                {
                    cancelScanButton.Visibility = Visibility.Collapsed;
                }
                
                var statusText = FindName("StatusText") as TextBlock;
                if (statusText != null)
                {
                    statusText.Text = "Scan cancelled";
                }
                
                _progressTimer?.Stop();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error cancelling scan: {ex.Message}", "Cancel Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void CopyFilePath_Click(object sender, RoutedEventArgs e) { }
        private async void TerminateSelectedProcess_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var processDataGrid = FindName("ProcessDataGrid") as DataGrid;
                if (processDataGrid?.SelectedItem is ProcessInfo selectedProcess)
                {
                    var result = MessageBox.Show(
                        $"Are you sure you want to terminate '{selectedProcess.Name}' (PID: {selectedProcess.Id})?\n\nThis action cannot be undone.",
                        "Confirm Process Termination",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    
                    if (result == MessageBoxResult.Yes)
                    {
                        try
                        {
                            var processController = new ProcessController();
                            bool success = await processController.TerminateProcessSafelyAsync(selectedProcess);
                            
                            if (success)
                            {
                                MessageBox.Show($"Process '{selectedProcess.Name}' has been terminated successfully.", 
                                              "Process Terminated", MessageBoxButton.OK, MessageBoxImage.Information);
                                
                                // Refresh the process list
                                await LoadProcessListAsync();
                            }
                            else
                            {
                                MessageBox.Show($"Failed to terminate process '{selectedProcess.Name}'. The process may be protected or require elevated privileges.", 
                                              "Termination Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Error terminating process: {ex.Message}", 
                                          "Termination Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            Debug.WriteLine($"❌ Process termination error: {ex.Message}");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Please select a process to terminate.", "No Process Selected", 
                                  MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ TerminateSelectedProcess_Click error: {ex.Message}");
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void ProcessDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                var dataGrid = sender as DataGrid;
                var endTaskButton = FindName("EndTaskButton") as Button;
                
                if (dataGrid?.SelectedItem != null && endTaskButton != null)
                {
                    // Enable End Task button when a process is selected
                    endTaskButton.IsEnabled = true;
                    Debug.WriteLine($"🎯 Process selected: {((ProcessInfo)dataGrid.SelectedItem).Name}");
                }
                else if (endTaskButton != null)
                {
                    // Disable End Task button when no process is selected
                    endTaskButton.IsEnabled = false;
                    Debug.WriteLine("🚫 No process selected");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ ProcessDataGrid_SelectionChanged error: {ex.Message}");
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            try
            {
                _keyboardHookService?.Stop();
                _keyboardHookService?.Dispose();
                _progressTimer?.Stop();
                _processRefreshTimer?.Stop();
            }
            catch { }
            
            base.OnClosed(e);
        }

        // Integration methods for other services to log threats
        public void LogScanResult(ScanResult scanResult)
        {
            if (_settingsService.CurrentSettings.LogScanResults)
            {
                _threatHistoryService.AddScanResult(scanResult);
            }
        }

        public void LogProcessTermination(string processName, int processId)
        {
            _threatHistoryService.AddProcessTermination(processName, processId);
        }

        public void LogSuspiciousProcess(ProcessInfo processInfo)
        {
            _threatHistoryService.AddSuspiciousProcess(processInfo);
        }

        public void LogKeyloggerActivity(string processName, string windowTitle)
        {
            _threatHistoryService.AddKeyloggerActivity(processName, windowTitle);
        }

        public void LogScanCompletion(int filesScanned, int threatsDetected, TimeSpan duration)
        {
            _threatHistoryService.AddScanCompletion(filesScanned, threatsDetected, duration);
        }

        // Process Monitor Basic Event Handlers
        private void ProcessSearchBox_GotFocus(object sender, RoutedEventArgs e)
        {
            if (sender is TextBox textBox && textBox.Text == "Search processes...")
            {
                textBox.Text = "";
                textBox.Foreground = new SolidColorBrush(Colors.White);
            }
        }

        private void ProcessSearchBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (sender is TextBox textBox && string.IsNullOrWhiteSpace(textBox.Text))
            {
                textBox.Text = "Search processes...";
                textBox.Foreground = new SolidColorBrush(Colors.Gray);
            }
        }

        private void ShowSystemProcesses_Changed(object sender, RoutedEventArgs e)
        {
            ApplyProcessFilters();
        }

        private void AutoRefresh_Changed(object sender, RoutedEventArgs e)
        {
            // Handle auto refresh toggle
            if (sender is CheckBox checkBox)
            {
                if (checkBox.IsChecked == true)
                {
                    _processRefreshTimer?.Start();
                }
                else
                {
                    _processRefreshTimer?.Stop();
                }
            }
        }

        // Process Monitor Enhanced Filtering Methods
        private void ThreatLevelFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            Debug.WriteLine("🔍 ThreatLevelFilter_Changed event triggered");
            ApplyProcessFilters();
        }

        private void ProcessTypeFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            ApplyProcessFilters();
        }

        private void ShowSystemCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            ApplyProcessFilters();
        }

        private void AutoRefreshCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            var autoRefreshCheckBox = sender as CheckBox;
            var refreshIntervalTextBox = FindName("RefreshIntervalTextBox") as TextBox;
            
            if (autoRefreshCheckBox?.IsChecked == true)
            {
                // Enable auto-refresh
                int intervalSeconds = 3; // Default to 3 seconds
                if (refreshIntervalTextBox != null && int.TryParse(refreshIntervalTextBox.Text, out int userInterval))
                {
                    intervalSeconds = Math.Max(1, userInterval); // Minimum 1 second
                }
                
                if (_processRefreshTimer == null)
                {
                    _processRefreshTimer = new DispatcherTimer();
                    _processRefreshTimer.Tick += async (s, args) => 
                    {
                        if (!_isLoadingProcesses)
                        {
                            await LoadProcessListAsync();
                        }
                    };
                }
                
                _processRefreshTimer.Interval = TimeSpan.FromSeconds(intervalSeconds);
                _processRefreshTimer.Start();
                
                Debug.WriteLine($"✅ Auto-refresh enabled: {intervalSeconds} seconds");
            }
            else
            {
                // Disable auto-refresh
                _processRefreshTimer?.Stop();
                Debug.WriteLine("🛑 Auto-refresh disabled");
            }
        }

        private void ProcessStatusFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            ApplyProcessFilters();
        }

        private void SearchTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            ApplyProcessFilters();
        }

        private void ApplyProcessFilters()
        {
            try
            {
                if (_isLoadingProcesses) return; // Prevent concurrent filtering
                
                if (_allProcesses == null || _allProcesses.Count == 0)
                {
                    Debug.WriteLine("⚠️ ApplyProcessFilters: No processes to filter, skipping");
                    return;
                }
                
                Debug.WriteLine($"🔍 ApplyProcessFilters called - using cached {_allProcesses.Count} processes");
                
                // Debug: Show threat level distribution
                var threatLevelCounts = _allProcesses.GroupBy(p => p.ThreatLevel).ToDictionary(g => g.Key, g => g.Count());
                Debug.WriteLine("🔍 Threat level distribution:");
                foreach (var kvp in threatLevelCounts)
                {
                    Debug.WriteLine($"  {kvp.Key}: {kvp.Value} processes");
                }
                
                // Use cached processes instead of re-scanning
                var filteredProcesses = _allProcesses.AsEnumerable();

                // Apply threat level filter
                var threatLevelFilter = FindName("ThreatLevelFilter") as ComboBox;
                if (threatLevelFilter?.SelectedItem is ComboBoxItem threatItem && threatItem.Content.ToString() != "All Threats")
                {
                    var selectedThreatLevel = threatItem.Content.ToString();
                    Debug.WriteLine($"🔍 Filtering by threat level: {selectedThreatLevel}");
                    var beforeCount = filteredProcesses.Count();
                    filteredProcesses = filteredProcesses.Where(p => 
                        p.ThreatLevel.Equals(selectedThreatLevel, StringComparison.OrdinalIgnoreCase));
                    var afterCount = filteredProcesses.Count();
                    Debug.WriteLine($"🔍 Threat level filter: {beforeCount} -> {afterCount} processes");
                }
                else
                {
                    Debug.WriteLine($"🔍 No threat level filter applied (control: {threatLevelFilter != null}, selected: {threatLevelFilter?.SelectedItem})");
                }

                // Apply process type filter
                var processTypeFilter = FindName("ProcessTypeFilter") as ComboBox;
                if (processTypeFilter?.SelectedItem is ComboBoxItem typeItem && typeItem.Content.ToString() != "All Processes")
                {
                    var selectedType = typeItem.Content.ToString();
                    Debug.WriteLine($"🔍 Filtering by process type: {selectedType}");
                    var beforeCount = filteredProcesses.Count();
                    filteredProcesses = selectedType switch
                    {
                        "System Applications" => filteredProcesses.Where(p => p.ProcessType == "System"),
                        "User Applications" => filteredProcesses.Where(p => p.ProcessType == "User"),
                        "Unknown/Suspicious" => filteredProcesses.Where(p => 
                            p.ProcessType == "Unknown" || 
                            p.ThreatLevel == "High" || 
                            p.ThreatLevel == "Critical"),
                        _ => filteredProcesses
                    };
                    var afterCount = filteredProcesses.Count();
                    Debug.WriteLine($"🔍 Process type filter: {beforeCount} -> {afterCount} processes");
                }
                else
                {
                    Debug.WriteLine($"🔍 No process type filter applied (control: {processTypeFilter != null}, selected: {processTypeFilter?.SelectedItem})");
                }

                // Apply Show System checkbox filter
                var showSystemCheckBox = FindName("ShowSystemCheckBox") as CheckBox;
                if (showSystemCheckBox?.IsChecked == false)
                {
                    Debug.WriteLine("🔍 Hiding system processes");
                    filteredProcesses = filteredProcesses.Where(p => p.ProcessType != "System");
                }

                // Apply search filter if search box exists
                var searchBox = FindName("ProcessSearchBox") as TextBox;
                if (searchBox != null && !string.IsNullOrEmpty(searchBox.Text) && searchBox.Text != "Search processes...")
                {
                    var searchTerm = searchBox.Text.ToLowerInvariant();
                    Debug.WriteLine($"🔍 Applying search filter: '{searchTerm}'");
                    filteredProcesses = filteredProcesses.Where(p =>
                        p.Name.ToLowerInvariant().Contains(searchTerm) ||
                        p.Id.ToString().Contains(searchTerm) ||
                        (!string.IsNullOrEmpty(p.Path) && p.Path.ToLowerInvariant().Contains(searchTerm)) ||
                        (!string.IsNullOrEmpty(p.Description) && p.Description.ToLowerInvariant().Contains(searchTerm)) ||
                        p.ThreatLevel.ToLowerInvariant().Contains(searchTerm) ||
                        p.ProcessType.ToLowerInvariant().Contains(searchTerm));
                }

                // Update the UI with filtered processes
                var finalCount = filteredProcesses.Count();
                Dispatcher.InvokeAsync(() =>
                {
                    ProcessList.Clear();
                    foreach (var process in filteredProcesses)
                    {
                        ProcessList.Add(process);
                    }

                    var processStatusText = FindName("ProcessStatusText") as TextBlock;
                    if (processStatusText != null)
                        processStatusText.Text = $"{ProcessList.Count} processes";

                    // Get filter states for final summary
                    var threatFilter = (FindName("ThreatLevelFilter") as ComboBox)?.SelectedItem as ComboBoxItem;
                    var typeFilter = (FindName("ProcessTypeFilter") as ComboBox)?.SelectedItem as ComboBoxItem;
                    var showSystem = (FindName("ShowSystemCheckBox") as CheckBox)?.IsChecked == true;
                    var searchText = (FindName("ProcessSearchBox") as TextBox)?.Text;
                    var hasSearch = !string.IsNullOrEmpty(searchText) && searchText != "Search processes...";

                    Debug.WriteLine($"🎯 FINAL FILTER SUMMARY:");
                    Debug.WriteLine($"   � Total processes: {_allProcesses?.Count ?? 0} → Final shown: {finalCount}");
                    Debug.WriteLine($"   �🔍 Threat Level: {threatFilter?.Content ?? "All"}");
                    Debug.WriteLine($"   🏷️  Process Type: {typeFilter?.Content ?? "All"}");
                    Debug.WriteLine($"   ⚙️  Show System: {showSystem}");
                    Debug.WriteLine($"   🔎 Search: {(hasSearch ? searchText : "None")}");
                    Debug.WriteLine($"✅ Applied filters: {ProcessList.Count} processes shown");
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Filter error: {ex.Message}");
            }
        }

        private async void InspectProcess_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Button button && button.CommandParameter is ProcessInfo selectedProcess)
                {
                    // Try to open File Explorer at the process location
                    if (!string.IsNullOrEmpty(selectedProcess.Path) && File.Exists(selectedProcess.Path))
                    {
                        // Open File Explorer and select the process file
                        System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{selectedProcess.Path}\"");
                        Debug.WriteLine($"🔍 Opened File Explorer for: {selectedProcess.Name} at {selectedProcess.Path}");
                    }
                    else if (!string.IsNullOrEmpty(selectedProcess.Path))
                    {
                        // Try to open the directory if the file doesn't exist
                        var directory = Path.GetDirectoryName(selectedProcess.Path);
                        if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory))
                        {
                            System.Diagnostics.Process.Start("explorer.exe", directory);
                            Debug.WriteLine($"🔍 Opened directory for: {selectedProcess.Name} at {directory}");
                        }
                        else
                        {
                            MessageBox.Show($"Process location not accessible:\n{selectedProcess.Path}", 
                                          "Location Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                    else
                    {
                        // Show process details if no path available
                        var details = $"Process: {selectedProcess.Name}\n" +
                                    $"PID: {selectedProcess.Id}\n" +
                                    $"Threat Level: {selectedProcess.ThreatLevel}\n" +
                                    $"Description: {selectedProcess.Description ?? "N/A"}\n" +
                                    $"Path: {selectedProcess.Path ?? "System Process"}";

                        MessageBox.Show(details, $"Process Details - {selectedProcess.Name}", 
                                      MessageBoxButton.OK, MessageBoxImage.Information);
                        Debug.WriteLine($"ℹ️ Showed details for: {selectedProcess.Name} (no path available)");
                    }
                }
                else
                {
                    MessageBox.Show("Please select a process to inspect.", "No Selection", 
                                  MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening process location: {ex.Message}", "Error", 
                              MessageBoxButton.OK, MessageBoxImage.Error);
                Debug.WriteLine($"❌ Error in InspectProcess_Click: {ex.Message}");
            }
        }

        private async Task<ProcessInspectionResult> InspectProcessDetailed(ProcessInfo processInfo)
        {
            var result = new ProcessInspectionResult
            {
                ProcessInfo = processInfo,
                InspectionTime = DateTime.Now
            };

            try
            {
                using (var process = Process.GetProcessById(processInfo.Id))
                {
                    // Get detailed process information
                    result.StartTime = process.StartTime;
                    result.TotalProcessorTime = process.TotalProcessorTime;
                    result.WorkingSet = process.WorkingSet64;
                    result.VirtualMemorySize = process.VirtualMemorySize64;
                    result.PrivateMemorySize = process.PrivateMemorySize64;
                    result.HandleCount = process.HandleCount;
                    result.ThreadCount = process.Threads.Count;

                    // Check for loaded modules
                    try
                    {
                        result.LoadedModules = process.Modules.Cast<ProcessModule>()
                            .Select(m => m.FileName)
                            .ToList();
                    }
                    catch
                    {
                        result.LoadedModules = new List<string> { "Access denied" };
                    }

                    // Perform additional threat analysis
                    var threatAnalysisResult = await _threatDetector.AnalyzeProcessAsync(processInfo);
                    result.ThreatAnalysis = threatAnalysisResult.ToString();
                    result.RiskFactors = GetProcessRiskFactors(processInfo, process);
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }
        
        #region Playground Helper Methods
        
        private string GetProcessFilePath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Unknown";
            }
            catch
            {
                return "Access Denied";
            }
        }
        
        private bool IsSystemProcess(string processName)
        {
            var systemProcesses = new[] { "System", "csrss", "winlogon", "services", "lsass", "svchost", "explorer", "dwm" };
            return systemProcesses.Any(sp => sp.Equals(processName, StringComparison.OrdinalIgnoreCase));
        }
        
        private void UpdatePlaygroundStatistics()
        {
            try
            {
                // Update monitored apps count
                var monitoredAppsCount = FindName("MonitoredAppsCount") as TextBlock;
                var activeAppCount = FindName("ActiveAppCount") as TextBlock;
                var logEntriesCount = FindName("LogEntriesCount") as TextBlock;
                var totalEventsCount = FindName("TotalEventsCount") as TextBlock;
                var activeAppsStatsCount = FindName("ActiveAppsStatsCount") as TextBlock;
                
                if (monitoredAppsCount != null)
                    monitoredAppsCount.Text = MonitoredApps.Count.ToString();
                    
                if (activeAppCount != null)
                    activeAppCount.Text = $"{MonitoredApps.Count} apps";
                    
                if (logEntriesCount != null)
                    logEntriesCount.Text = $"{ActivityLog.Count} entries";
                    
                if (totalEventsCount != null)
                    totalEventsCount.Text = ActivityLog.Count.ToString();
                    
                if (activeAppsStatsCount != null)
                    activeAppsStatsCount.Text = MonitoredApps.Count.ToString();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating playground statistics: {ex.Message}");
            }
        }
        
        #endregion
        
        #region Playground Event Handlers
        
        private void RefreshAppsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Clear the existing monitored applications list
                MonitoredApps.Clear();
                
                // Add refresh log entry
                var logEntry = new ActivityLogEntry
                {
                    ApplicationName = "KeyGuard Pro",
                    ProcessId = Process.GetCurrentProcess().Id,
                    EventType = "Manual Refresh",
                    Details = "Application list cleared and refreshed",
                    Severity = "INFO"
                };
                ActivityLog.Insert(0, logEntry);
                
                UpdatePlaygroundStatistics();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error refreshing application list: {ex.Message}", "Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void LocateFileButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var applicationsDataGrid = FindName("ApplicationsDataGrid") as DataGrid;
                if (applicationsDataGrid?.SelectedItem is MonitoredApplication selectedApp)
                {
                    if (!string.IsNullOrEmpty(selectedApp.FilePath) && selectedApp.FilePath != "Unknown" && selectedApp.FilePath != "Access Denied")
                    {
                        if (File.Exists(selectedApp.FilePath))
                        {
                            // Open file location in Windows Explorer
                            System.Diagnostics.Process.Start(new ProcessStartInfo
                            {
                                FileName = "explorer.exe",
                                Arguments = $"/select,\"{selectedApp.FilePath}\"",
                                UseShellExecute = false
                            });
                            
                            // Add log entry
                            var logEntry = new ActivityLogEntry
                            {
                                ApplicationName = selectedApp.ApplicationName,
                                ProcessId = selectedApp.ProcessId,
                                EventType = "File Located",
                                Details = $"Opened file location: {selectedApp.FilePath}",
                                Severity = "INFO"
                            };
                            ActivityLog.Insert(0, logEntry);
                        }
                        else
                        {
                            MessageBox.Show($"File not found: {selectedApp.FilePath}", "File Not Found", 
                                           MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                    else
                    {
                        MessageBox.Show("File path is not available for this application.", "No File Path", 
                                       MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                else
                {
                    MessageBox.Show("Please select an application from the list.", "No Selection", 
                                   MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error locating file: {ex.Message}", "Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void TerminateProcessButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var applicationsDataGrid = FindName("ApplicationsDataGrid") as DataGrid;
                if (applicationsDataGrid?.SelectedItem is MonitoredApplication selectedApp)
                {
                    var result = MessageBox.Show(
                        $"Are you sure you want to terminate the process '{selectedApp.ApplicationName}' (PID: {selectedApp.ProcessId})?\n\nThis action cannot be undone.",
                        "Confirm Process Termination",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                        
                    if (result == MessageBoxResult.Yes)
                    {
                        try
                        {
                            var process = Process.GetProcessById(selectedApp.ProcessId);
                            process.Kill();
                            
                            // Remove from monitored apps list
                            MonitoredApps.Remove(selectedApp);
                            
                            // Add log entry
                            var logEntry = new ActivityLogEntry
                            {
                                ApplicationName = selectedApp.ApplicationName,
                                ProcessId = selectedApp.ProcessId,
                                EventType = "Process Terminated",
                                Details = $"Process {selectedApp.ApplicationName} (PID: {selectedApp.ProcessId}) was terminated by user",
                                Severity = "WARNING"
                            };
                            ActivityLog.Insert(0, logEntry);
                            
                            UpdatePlaygroundStatistics();
                            
                            MessageBox.Show($"Process '{selectedApp.ApplicationName}' has been terminated.", "Process Terminated", 
                                           MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                        catch (ArgumentException)
                        {
                            // Process already exited
                            MonitoredApps.Remove(selectedApp);
                            UpdatePlaygroundStatistics();
                            MessageBox.Show("Process has already exited.", "Process Not Found", 
                                           MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            MessageBox.Show("Access denied. Cannot terminate this process. Try running as Administrator.", 
                                           "Access Denied", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Please select an application from the list.", "No Selection", 
                                   MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error terminating process: {ex.Message}", "Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = MessageBox.Show("Are you sure you want to clear the activity log?", "Clear Log", 
                                           MessageBoxButton.YesNo, MessageBoxImage.Question);
                                           
                if (result == MessageBoxResult.Yes)
                {
                    ActivityLog.Clear();
                    
                    // Add a new log entry indicating the log was cleared
                    var logEntry = new ActivityLogEntry
                    {
                        ApplicationName = "KeyGuard Pro",
                        ProcessId = Process.GetCurrentProcess().Id,
                        EventType = "Log Cleared",
                        Details = "Activity log was manually cleared by user",
                        Severity = "INFO"
                    };
                    ActivityLog.Insert(0, logEntry);
                    
                    UpdatePlaygroundStatistics();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error clearing log: {ex.Message}", "Error", 
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        #endregion
        
        private List<string> GetProcessRiskFactors(ProcessInfo processInfo, Process process)
        {
            var riskFactors = new List<string>();

            if (processInfo.HasKeyboardHooks)
                riskFactors.Add("Has keyboard hooks installed");

            if (processInfo.CpuUsage > 20)
                riskFactors.Add($"High CPU usage: {processInfo.CpuUsage:F1}%");

            if (processInfo.MemoryUsage > 500 * 1024 * 1024) // 500MB
                riskFactors.Add($"High memory usage: {processInfo.MemoryUsage / (1024 * 1024):F0} MB");

            if (processInfo.Path.ToLowerInvariant().Contains("temp") || 
                processInfo.Path.ToLowerInvariant().Contains("appdata"))
                riskFactors.Add("Running from temporary directory");

            if (!File.Exists(processInfo.Path))
                riskFactors.Add("Executable file no longer exists");

            try
            {
                var fileInfo = new FileInfo(processInfo.Path);
                if ((DateTime.Now - fileInfo.CreationTime).TotalDays < 1)
                    riskFactors.Add("Recently created executable");
            }
            catch { /* Ignore file access errors */ }

            return riskFactors;
        }

        private void ShowProcessInspectionDialog(ProcessInfo processInfo, ProcessInspectionResult inspectionResult)
        {
            var dialog = new Window
            {
                Title = $"Process Inspection - {processInfo.Name}",
                Width = 600,
                Height = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30")),
                Foreground = new SolidColorBrush(Colors.White)
            };

            var scrollViewer = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(20)
            };

            var stackPanel = new StackPanel();

            // Process basic info
            stackPanel.Children.Add(new TextBlock
            {
                Text = "Process Information",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            });

            stackPanel.Children.Add(new TextBlock
            {
                Text = $"Name: {processInfo.Name}\n" +
                       $"PID: {processInfo.Id}\n" +
                       $"Path: {processInfo.Path}\n" +
                       $"Threat Level: {processInfo.ThreatLevel}\n" +
                       $"Has Hooks: {(processInfo.HasKeyboardHooks ? "Yes" : "No")}\n" +
                       $"CPU Usage: {processInfo.CpuUsage:F1}%\n" +
                       $"Memory Usage: {processInfo.MemoryUsage / (1024 * 1024):F1} MB",
                Margin = new Thickness(0, 0, 0, 20),
                TextWrapping = TextWrapping.Wrap
            });

            if (!string.IsNullOrEmpty(inspectionResult.ErrorMessage))
            {
                stackPanel.Children.Add(new TextBlock
                {
                    Text = $"Error: {inspectionResult.ErrorMessage}",
                    Foreground = new SolidColorBrush(Colors.Red),
                    Margin = new Thickness(0, 0, 0, 10)
                });
            }
            else
            {
                // Detailed inspection results
                stackPanel.Children.Add(new TextBlock
                {
                    Text = "Detailed Analysis",
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 10)
                });

                stackPanel.Children.Add(new TextBlock
                {
                    Text = $"Start Time: {inspectionResult.StartTime}\n" +
                           $"Total CPU Time: {inspectionResult.TotalProcessorTime}\n" +
                           $"Working Set: {inspectionResult.WorkingSet / (1024 * 1024):F1} MB\n" +
                           $"Virtual Memory: {inspectionResult.VirtualMemorySize / (1024 * 1024):F1} MB\n" +
                           $"Private Memory: {inspectionResult.PrivateMemorySize / (1024 * 1024):F1} MB\n" +
                           $"Handle Count: {inspectionResult.HandleCount}\n" +
                           $"Thread Count: {inspectionResult.ThreadCount}",
                    Margin = new Thickness(0, 0, 0, 20)
                });

                // Risk factors
                if (inspectionResult.RiskFactors.Any())
                {
                    stackPanel.Children.Add(new TextBlock
                    {
                        Text = "Risk Factors",
                        FontSize = 16,
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(Colors.Orange),
                        Margin = new Thickness(0, 0, 0, 10)
                    });

                    foreach (var risk in inspectionResult.RiskFactors)
                    {
                        stackPanel.Children.Add(new TextBlock
                        {
                            Text = $"• {risk}",
                            Foreground = new SolidColorBrush(Colors.Orange),
                            Margin = new Thickness(10, 0, 0, 5)
                        });
                    }
                }
            }

            scrollViewer.Content = stackPanel;
            dialog.Content = scrollViewer;
            dialog.ShowDialog();
        }
    }

    // Helper class for detailed process inspection
    public class ProcessInspectionResult
    {
        public ProcessInfo ProcessInfo { get; set; }
        public DateTime InspectionTime { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan TotalProcessorTime { get; set; }
        public long WorkingSet { get; set; }
        public long VirtualMemorySize { get; set; }
        public long PrivateMemorySize { get; set; }
        public int HandleCount { get; set; }
        public int ThreadCount { get; set; }
        public List<string> LoadedModules { get; set; } = new List<string>();
        public string ThreatAnalysis { get; set; }
        public List<string> RiskFactors { get; set; } = new List<string>();
        public string ErrorMessage { get; set; }
    }
}
