using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace KeyloggerDetector.Models
{
    public class AppSettings : INotifyPropertyChanged
    {
        private string _virusTotalApiKey = "";
        private bool _enableVirusTotalScanning = true;
        private bool _includeSubfoldersDefault = true;
        private bool _enableRealtimeMonitoring = false;
        private bool _showSystemProcesses = true;
        private bool _autoRefreshProcesses = true;
        private int _refreshIntervalSeconds = 5;
        private bool _enableDarkTheme = true;
        private bool _showThreatNotifications = true;
        private bool _logScanResults = true;
        private int _maxHistoryDays = 30;
        private bool _enableAutoScan = false;
        private string _autoScanFolder = "";
        private int _autoScanIntervalMinutes = 60;

        public string VirusTotalApiKey
        {
            get => _virusTotalApiKey;
            set
            {
                _virusTotalApiKey = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsVirusTotalConfigured));
            }
        }

        public bool EnableVirusTotalScanning
        {
            get => _enableVirusTotalScanning;
            set
            {
                _enableVirusTotalScanning = value;
                OnPropertyChanged();
            }
        }

        public bool IncludeSubfoldersDefault
        {
            get => _includeSubfoldersDefault;
            set
            {
                _includeSubfoldersDefault = value;
                OnPropertyChanged();
            }
        }

        public bool EnableRealtimeMonitoring
        {
            get => _enableRealtimeMonitoring;
            set
            {
                _enableRealtimeMonitoring = value;
                OnPropertyChanged();
            }
        }

        public bool ShowSystemProcesses
        {
            get => _showSystemProcesses;
            set
            {
                _showSystemProcesses = value;
                OnPropertyChanged();
            }
        }

        public bool AutoRefreshProcesses
        {
            get => _autoRefreshProcesses;
            set
            {
                _autoRefreshProcesses = value;
                OnPropertyChanged();
            }
        }

        public int RefreshIntervalSeconds
        {
            get => _refreshIntervalSeconds;
            set
            {
                _refreshIntervalSeconds = value;
                OnPropertyChanged();
            }
        }

        public bool EnableDarkTheme
        {
            get => _enableDarkTheme;
            set
            {
                _enableDarkTheme = value;
                OnPropertyChanged();
            }
        }

        public bool ShowThreatNotifications
        {
            get => _showThreatNotifications;
            set
            {
                _showThreatNotifications = value;
                OnPropertyChanged();
            }
        }

        public bool LogScanResults
        {
            get => _logScanResults;
            set
            {
                _logScanResults = value;
                OnPropertyChanged();
            }
        }

        public int MaxHistoryDays
        {
            get => _maxHistoryDays;
            set
            {
                _maxHistoryDays = value;
                OnPropertyChanged();
            }
        }

        public bool EnableAutoScan
        {
            get => _enableAutoScan;
            set
            {
                _enableAutoScan = value;
                OnPropertyChanged();
            }
        }

        public string AutoScanFolder
        {
            get => _autoScanFolder;
            set
            {
                _autoScanFolder = value;
                OnPropertyChanged();
            }
        }

        public int AutoScanIntervalMinutes
        {
            get => _autoScanIntervalMinutes;
            set
            {
                _autoScanIntervalMinutes = value;
                OnPropertyChanged();
            }
        }

        [JsonIgnore]
        public bool IsVirusTotalConfigured => !string.IsNullOrWhiteSpace(VirusTotalApiKey);

        [JsonIgnore]
        public string ApiKeyStatus => IsVirusTotalConfigured ? "✅ Configured" : "❌ Not Set";

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
