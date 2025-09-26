using System;
using System.ComponentModel;

namespace KeyloggerDetector.Models
{
    public class MonitoredApplication : INotifyPropertyChanged
    {
        private string _applicationName;
        private int _processId;
        private int _inputCount;
        private string _lastActivity;
        private string _filePath;
        private DateTime _firstDetected;
        private DateTime _lastInputTime;
        private bool _isSystemApp;

        public string ApplicationName
        {
            get => _applicationName;
            set
            {
                _applicationName = value;
                OnPropertyChanged(nameof(ApplicationName));
            }
        }

        public int ProcessId
        {
            get => _processId;
            set
            {
                _processId = value;
                OnPropertyChanged(nameof(ProcessId));
            }
        }

        public int InputCount
        {
            get => _inputCount;
            set
            {
                _inputCount = value;
                OnPropertyChanged(nameof(InputCount));
            }
        }

        public string LastActivity
        {
            get => GetTimeAgo(_lastInputTime);
            set
            {
                _lastActivity = value;
                OnPropertyChanged(nameof(LastActivity));
            }
        }

        public string FilePath
        {
            get => _filePath;
            set
            {
                _filePath = value;
                OnPropertyChanged(nameof(FilePath));
            }
        }

        public DateTime FirstDetected
        {
            get => _firstDetected;
            set
            {
                _firstDetected = value;
                OnPropertyChanged(nameof(FirstDetected));
            }
        }

        public DateTime LastInputTime
        {
            get => _lastInputTime;
            set
            {
                _lastInputTime = value;
                OnPropertyChanged(nameof(LastInputTime));
                OnPropertyChanged(nameof(LastActivity)); // Trigger LastActivity update
            }
        }

        public bool IsSystemApp
        {
            get => _isSystemApp;
            set
            {
                _isSystemApp = value;
                OnPropertyChanged(nameof(IsSystemApp));
            }
        }

        public MonitoredApplication()
        {
            FirstDetected = DateTime.Now;
            LastInputTime = DateTime.Now;
            InputCount = 0;
        }

        public void IncrementInputCount()
        {
            InputCount++;
            LastInputTime = DateTime.Now;
        }

        private string GetTimeAgo(DateTime time)
        {
            var span = DateTime.Now - time;
            
            if (span.TotalSeconds < 5)
                return "Just now";
            else if (span.TotalSeconds < 60)
                return $"{(int)span.TotalSeconds}s";
            else if (span.TotalMinutes < 60)
                return $"{(int)span.TotalMinutes}min";
            else if (span.TotalHours < 24)
                return $"{(int)span.TotalHours}h";
            else
                return $"{(int)span.TotalDays}d";
        }
        
        public void UpdateLastActivity()
        {
            // Force refresh of LastActivity display
            OnPropertyChanged(nameof(LastActivity));
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class ActivityLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string ApplicationName { get; set; }
        public int ProcessId { get; set; }
        public string EventType { get; set; }
        public string Details { get; set; }
        public string Severity { get; set; }

        public string FormattedTimestamp => Timestamp.ToString("HH:mm:ss.fff");
        public string FormattedMessage => $"[{FormattedTimestamp}] [{Severity}] {ApplicationName} (PID:{ProcessId}) - {EventType}: {Details}";

        public ActivityLogEntry()
        {
            Timestamp = DateTime.Now;
            Severity = "INFO";
        }
    }
}
