using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;

namespace KeyloggerDetector.Models
{
    public class ScanResult : INotifyPropertyChanged
    {
        private string _fileName;
        private string _filePath;
        private string _status;
        private long _fileSize;
        private int _detectionCount;
        private int _totalScans;
        private List<string> _threatNames;
        private string _md5Hash;
        private string _sha1Hash;
        private string _sha256Hash;
        private DateTime _scanDate;
        private bool _isMalicious;

        public string FileName
        {
            get => _fileName;
            set
            {
                _fileName = value;
                OnPropertyChanged();
            }
        }

        public string FilePath
        {
            get => _filePath;
            set
            {
                _filePath = value;
                OnPropertyChanged();
            }
        }

        public string Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged();
            }
        }

        public long FileSize
        {
            get => _fileSize;
            set
            {
                _fileSize = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FileSizeFormatted));
            }
        }

        public string FileSizeFormatted
        {
            get
            {
                if (FileSize < 1024)
                    return $"{FileSize} B";
                else if (FileSize < 1024 * 1024)
                    return $"{FileSize / 1024:F1} KB";
                else if (FileSize < 1024 * 1024 * 1024)
                    return $"{FileSize / (1024 * 1024):F1} MB";
                else
                    return $"{FileSize / (1024 * 1024 * 1024):F1} GB";
            }
        }

        public int DetectionCount
        {
            get => _detectionCount;
            set
            {
                _detectionCount = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DetectionRatio));
            }
        }

        public int TotalScans
        {
            get => _totalScans;
            set
            {
                _totalScans = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DetectionRatio));
            }
        }

        public string DetectionRatio => TotalScans > 0 ? $"{DetectionCount}/{TotalScans}" : "0/0";

        public List<string> ThreatNames
        {
            get => _threatNames ?? new List<string>();
            set
            {
                _threatNames = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ThreatNamesFormatted));
            }
        }

        public string ThreatNamesFormatted => ThreatNames?.Any() == true ? string.Join(", ", ThreatNames) : "Clean";

        public string MD5Hash
        {
            get => _md5Hash;
            set
            {
                _md5Hash = value;
                OnPropertyChanged();
            }
        }

        public string SHA1Hash
        {
            get => _sha1Hash;
            set
            {
                _sha1Hash = value;
                OnPropertyChanged();
            }
        }

        public string SHA256Hash
        {
            get => _sha256Hash;
            set
            {
                _sha256Hash = value;
                OnPropertyChanged();
            }
        }

        public DateTime ScanDate
        {
            get => _scanDate;
            set
            {
                _scanDate = value;
                OnPropertyChanged();
            }
        }

        public bool IsMalicious
        {
            get => _isMalicious;
            set
            {
                _isMalicious = value;
                OnPropertyChanged();
            }
        }

        public ScanResult()
        {
            ScanDate = DateTime.Now;
            ThreatNames = new List<string>();
        }

        public ScanResult(string filePath)
        {
            FilePath = filePath;
            FileName = Path.GetFileName(filePath);
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                FileSize = fileInfo.Length;
            }
            catch
            {
                FileSize = 0;
            }

            Status = "Pending";
            ScanDate = DateTime.Now;
            ThreatNames = new List<string>();
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
