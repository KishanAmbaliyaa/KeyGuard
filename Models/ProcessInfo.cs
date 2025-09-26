using System;
using System.ComponentModel;

namespace KeyloggerDetector.Models
{
    public class ProcessInfo : INotifyPropertyChanged
    {
        private string _name;
        private int _id;
        private string _path;
        private bool _hasKeyboardHooks;
        private bool _hasSystemAccess;
        private string _threatLevel;
        private double _cpuUsage;
        private long _memoryUsage;
        private string _description;
        private bool _isSuspicious;

        public string Name
        {
            get => _name;
            set { _name = value; OnPropertyChanged(nameof(Name)); }
        }

        public int Id
        {
            get => _id;
            set { _id = value; OnPropertyChanged(nameof(Id)); }
        }

        public string Path
        {
            get => _path;
            set { _path = value; OnPropertyChanged(nameof(Path)); }
        }

        public bool HasKeyboardHooks
        {
            get => _hasKeyboardHooks;
            set { _hasKeyboardHooks = value; OnPropertyChanged(nameof(HasKeyboardHooks)); }
        }

        public bool HasSystemAccess
        {
            get => _hasSystemAccess;
            set { _hasSystemAccess = value; OnPropertyChanged(nameof(HasSystemAccess)); }
        }

        public string ThreatLevel
        {
            get => _threatLevel;
            set 
            { 
                _threatLevel = value; 
                OnPropertyChanged(nameof(ThreatLevel));
                OnPropertyChanged(nameof(ThreatLevelColor));
            }
        }

        // Color information as string for console/non-WPF applications
        public string ThreatLevelColor
        {
            get
            {
                return ThreatLevel switch
                {
                    "High" => "Red",
                    "Medium" => "Orange", 
                    "Low" => "Yellow",
                    _ => "Green"
                };
            }
        }        public double CpuUsage
        {
            get => _cpuUsage;
            set { _cpuUsage = value; OnPropertyChanged(nameof(CpuUsage)); OnPropertyChanged(nameof(CpuUsageFormatted)); }
        }

        public string CpuUsageFormatted
        {
            get
            {
                if (CpuUsage < 0.1) return "0%";
                return $"{CpuUsage:F1}%";
            }
        }

        public long MemoryUsage
        {
            get => _memoryUsage;
            set { _memoryUsage = value; OnPropertyChanged(nameof(MemoryUsage)); OnPropertyChanged(nameof(MemoryUsageMB)); OnPropertyChanged(nameof(MemoryUsageFormatted)); }
        }

        public string MemoryUsageMB
        {
            get
            {
                if (MemoryUsage == 0) return "N/A";
                double mb = MemoryUsage / (1024.0 * 1024.0);
                return $"{mb:F1} MB";
            }
        }

        public string MemoryUsageFormatted
        {
            get
            {
                if (MemoryUsage == 0) return "N/A";
                
                double bytes = MemoryUsage;
                string[] sizes = { "B", "KB", "MB", "GB" };
                int order = 0;
                
                while (bytes >= 1024 && order < sizes.Length - 1)
                {
                    bytes /= 1024;
                    order++;
                }
                
                return $"{bytes:F1} {sizes[order]}";
            }
        }

        public string Description
        {
            get => _description;
            set { _description = value; OnPropertyChanged(nameof(Description)); }
        }

        public bool IsSuspicious
        {
            get => _isSuspicious;
            set { _isSuspicious = value; OnPropertyChanged(nameof(IsSuspicious)); }
        }

        private string _processType = "Unknown";
        public string ProcessType
        {
            get => _processType;
            set { _processType = value; OnPropertyChanged(nameof(ProcessType)); }
        }

        public DateTime LastScanned { get; set; } = DateTime.Now;

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
