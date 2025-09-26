using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace KeyloggerDetector.Models
{
    public enum ThreatEventType
    {
        FileScanned,
        ThreatDetected,
        ProcessTerminated,
        SuspiciousProcessDetected,
        KeyloggerActivityDetected,
        ScanCompleted,
        SystemEvent
    }

    public enum ThreatSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    public enum ThreatStatus
    {
        Active,
        Resolved,
        Dismissed,
        InProgress
    }

    public class ThreatHistoryEntry : INotifyPropertyChanged
    {
        private DateTime _timestamp;
        private ThreatEventType _eventType;
        private ThreatSeverity _severity;
        private ThreatStatus _status;
        private string _title;
        private string _description;
        private string _source;
        private string _details;
        private bool _isResolved;
        private string _actionTaken;
        private int _affectedFiles;
        private long _scanDuration;

        public DateTime Timestamp
        {
            get => _timestamp;
            set
            {
                _timestamp = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TimeAgo));
                OnPropertyChanged(nameof(FormattedTime));
            }
        }

        public ThreatEventType EventType
        {
            get => _eventType;
            set
            {
                _eventType = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(EventTypeIcon));
                OnPropertyChanged(nameof(EventTypeText));
            }
        }

        public ThreatSeverity Severity
        {
            get => _severity;
            set
            {
                _severity = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SeverityColor));
                OnPropertyChanged(nameof(SeverityIcon));
            }
        }

        public ThreatStatus Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(StatusColor));
            }
        }

        public string Title
        {
            get => _title;
            set
            {
                _title = value;
                OnPropertyChanged();
            }
        }

        public string Description
        {
            get => _description;
            set
            {
                _description = value;
                OnPropertyChanged();
            }
        }

        public string Source
        {
            get => _source;
            set
            {
                _source = value;
                OnPropertyChanged();
            }
        }

        public string Details
        {
            get => _details;
            set
            {
                _details = value;
                OnPropertyChanged();
            }
        }

        public bool IsResolved
        {
            get => _isResolved;
            set
            {
                _isResolved = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(StatusColor));
            }
        }

        public string ActionTaken
        {
            get => _actionTaken;
            set
            {
                _actionTaken = value;
                OnPropertyChanged();
            }
        }

        public int AffectedFiles
        {
            get => _affectedFiles;
            set
            {
                _affectedFiles = value;
                OnPropertyChanged();
            }
        }

        public long ScanDuration
        {
            get => _scanDuration;
            set
            {
                _scanDuration = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedDuration));
            }
        }

        // Computed Properties
        public string TimeAgo
        {
            get
            {
                var timeSpan = DateTime.Now - Timestamp;
                if (timeSpan.TotalMinutes < 1)
                    return "Just now";
                if (timeSpan.TotalHours < 1)
                    return $"{(int)timeSpan.TotalMinutes}m ago";
                if (timeSpan.TotalDays < 1)
                    return $"{(int)timeSpan.TotalHours}h ago";
                if (timeSpan.TotalDays < 7)
                    return $"{(int)timeSpan.TotalDays}d ago";
                return Timestamp.ToString("MMM dd, yyyy");
            }
        }

        public string FormattedTime => Timestamp.ToString("MMM dd, yyyy HH:mm:ss");

        public string FormattedDuration
        {
            get
            {
                if (ScanDuration < 1000)
                    return $"{ScanDuration}ms";
                var seconds = ScanDuration / 1000.0;
                if (seconds < 60)
                    return $"{seconds:F1}s";
                var minutes = seconds / 60.0;
                return $"{minutes:F1}m";
            }
        }

        public string EventTypeIcon
        {
            get
            {
                return EventType switch
                {
                    ThreatEventType.FileScanned => "📄",
                    ThreatEventType.ThreatDetected => "⚠️",
                    ThreatEventType.ProcessTerminated => "🔴",
                    ThreatEventType.SuspiciousProcessDetected => "👀",
                    ThreatEventType.KeyloggerActivityDetected => "⌨️",
                    ThreatEventType.ScanCompleted => "✅",
                    ThreatEventType.SystemEvent => "🔧",
                    _ => "📋"
                };
            }
        }

        public string EventTypeText
        {
            get
            {
                return EventType switch
                {
                    ThreatEventType.FileScanned => "File Scan",
                    ThreatEventType.ThreatDetected => "Threat Detected",
                    ThreatEventType.ProcessTerminated => "Process Terminated",
                    ThreatEventType.SuspiciousProcessDetected => "Suspicious Process",
                    ThreatEventType.KeyloggerActivityDetected => "Keylogger Activity",
                    ThreatEventType.ScanCompleted => "Scan Completed",
                    ThreatEventType.SystemEvent => "System Event",
                    _ => "Unknown"
                };
            }
        }

        public string SeverityIcon
        {
            get
            {
                return Severity switch
                {
                    ThreatSeverity.Info => "ℹ️",
                    ThreatSeverity.Low => "🟡",
                    ThreatSeverity.Medium => "🟠",
                    ThreatSeverity.High => "🔴",
                    ThreatSeverity.Critical => "💀",
                    _ => "⚪"
                };
            }
        }

        public string SeverityColor
        {
            get
            {
                return Severity switch
                {
                    ThreatSeverity.Info => "#4CAF50",
                    ThreatSeverity.Low => "#FFC107",
                    ThreatSeverity.Medium => "#FF9800",
                    ThreatSeverity.High => "#F44336",
                    ThreatSeverity.Critical => "#9C27B0",
                    _ => "#9E9E9E"
                };
            }
        }

        public string StatusText => Status switch
        {
            ThreatStatus.Active => "Active",
            ThreatStatus.Resolved => "Resolved", 
            ThreatStatus.Dismissed => "Dismissed",
            ThreatStatus.InProgress => "In Progress",
            _ => "Unknown"
        };

        public string StatusColor => Status switch
        {
            ThreatStatus.Active => "#FF9800",
            ThreatStatus.Resolved => "#4CAF50",
            ThreatStatus.Dismissed => "#9E9E9E", 
            ThreatStatus.InProgress => "#2196F3",
            _ => "#9E9E9E"
        };

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
