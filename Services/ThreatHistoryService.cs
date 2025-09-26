using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeyloggerDetector.Models;
using Newtonsoft.Json;

namespace KeyloggerDetector.Services
{
    public class ThreatHistoryService
    {
        private static readonly string HistoryFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "KeyGuardPro",
            "threat_history.json"
        );

        private readonly ObservableCollection<ThreatHistoryEntry> _history;
        private readonly object _lockObject = new object();

        public event EventHandler<ThreatHistoryEntry> ThreatEventAdded;
        public event EventHandler HistoryCleared;

        public ObservableCollection<ThreatHistoryEntry> History => _history;

        public ThreatHistoryService()
        {
            _history = new ObservableCollection<ThreatHistoryEntry>();
            
            // Ensure the history directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(HistoryFilePath));
            
            LoadHistory();
        }

        public void AddThreatEvent(ThreatHistoryEntry entry)
        {
            lock (_lockObject)
            {
                _history.Insert(0, entry); // Add to beginning for newest first
                ThreatEventAdded?.Invoke(this, entry);
                
                // Auto-save after adding
                _ = SaveHistoryAsync();
            }
        }

        public void AddScanResult(ScanResult scanResult)
        {
            var entry = new ThreatHistoryEntry
            {
                Timestamp = scanResult.ScanDate,
                EventType = scanResult.IsMalicious ? ThreatEventType.ThreatDetected : ThreatEventType.FileScanned,
                Severity = scanResult.IsMalicious ? GetSeverityFromDetection(scanResult) : ThreatSeverity.Info,
                Title = scanResult.IsMalicious ? $"Threat detected: {scanResult.FileName}" : $"File scanned: {scanResult.FileName}",
                Description = scanResult.IsMalicious 
                    ? $"Detected {scanResult.DetectionCount}/{scanResult.TotalScans} threats"
                    : "File scan completed successfully",
                Source = "File Scanner",
                Details = scanResult.IsMalicious 
                    ? $"Threats: {string.Join(", ", scanResult.ThreatNames ?? new List<string>())}"
                    : $"File: {scanResult.FilePath}",
                IsResolved = false,
                ActionTaken = scanResult.IsMalicious ? "File flagged for review" : "None required",
                AffectedFiles = 1,
                ScanDuration = 0 // Could be added to ScanResult later
            };

            AddThreatEvent(entry);
        }

        public void AddProcessTermination(string processName, int processId)
        {
            var entry = new ThreatHistoryEntry
            {
                Timestamp = DateTime.Now,
                EventType = ThreatEventType.ProcessTerminated,
                Severity = ThreatSeverity.Medium,
                Title = $"Process terminated: {processName}",
                Description = $"Suspicious process {processName} (PID: {processId}) was terminated",
                Source = "Process Monitor",
                Details = $"Process: {processName}\nPID: {processId}",
                IsResolved = true,
                ActionTaken = "Process terminated by user",
                AffectedFiles = 0,
                ScanDuration = 0
            };

            AddThreatEvent(entry);
        }

        public void AddSuspiciousProcess(ProcessInfo processInfo)
        {
            var entry = new ThreatHistoryEntry
            {
                Timestamp = DateTime.Now,
                EventType = ThreatEventType.SuspiciousProcessDetected,
                Severity = GetSeverityFromThreatLevel(processInfo.ThreatLevel),
                Title = $"Suspicious process detected: {processInfo.Name}",
                Description = $"Process {processInfo.Name} shows suspicious behavior",
                Source = "Process Monitor",
                Details = $"Process: {processInfo.Name}\nPID: {processInfo.Id}\nPath: {processInfo.Path}\nThreat Level: {processInfo.ThreatLevel}",
                IsResolved = false,
                ActionTaken = "Process flagged for review",
                AffectedFiles = 0,
                ScanDuration = 0
            };

            AddThreatEvent(entry);
        }

        public void AddKeyloggerActivity(string processName, string windowTitle)
        {
            var entry = new ThreatHistoryEntry
            {
                Timestamp = DateTime.Now,
                EventType = ThreatEventType.KeyloggerActivityDetected,
                Severity = ThreatSeverity.High,
                Title = "Potential keylogger activity detected",
                Description = $"Suspicious keyboard monitoring detected in {processName}",
                Source = "Keyboard Monitor",
                Details = $"Process: {processName}\nWindow: {windowTitle}",
                IsResolved = false,
                ActionTaken = "Activity logged for analysis",
                AffectedFiles = 0,
                ScanDuration = 0
            };

            AddThreatEvent(entry);
        }

        public void AddScanCompletion(int filesScanned, int threatsDetected, TimeSpan duration)
        {
            var entry = new ThreatHistoryEntry
            {
                Timestamp = DateTime.Now,
                EventType = ThreatEventType.ScanCompleted,
                Severity = threatsDetected > 0 ? ThreatSeverity.Medium : ThreatSeverity.Info,
                Title = $"Scan completed: {filesScanned} files scanned",
                Description = threatsDetected > 0 
                    ? $"Found {threatsDetected} threats in {filesScanned} files"
                    : $"No threats found in {filesScanned} files",
                Source = "File Scanner",
                Details = $"Files scanned: {filesScanned}\nThreats detected: {threatsDetected}\nDuration: {duration:mm\\:ss}",
                IsResolved = true,
                ActionTaken = "Scan completed successfully",
                AffectedFiles = filesScanned,
                ScanDuration = (long)duration.TotalMilliseconds
            };

            AddThreatEvent(entry);
        }

        public void MarkAsResolved(ThreatHistoryEntry entry, string action)
        {
            entry.IsResolved = true;
            entry.ActionTaken = action;
            _ = SaveHistoryAsync();
        }

        public List<ThreatHistoryEntry> GetFilteredHistory(
            ThreatEventType? eventType = null,
            ThreatSeverity? severity = null,
            DateTime? fromDate = null,
            DateTime? toDate = null,
            bool? isResolved = null)
        {
            lock (_lockObject)
            {
                var query = _history.AsEnumerable();

                if (eventType.HasValue)
                    query = query.Where(h => h.EventType == eventType.Value);

                if (severity.HasValue)
                    query = query.Where(h => h.Severity == severity.Value);

                if (fromDate.HasValue)
                    query = query.Where(h => h.Timestamp >= fromDate.Value);

                if (toDate.HasValue)
                    query = query.Where(h => h.Timestamp <= toDate.Value);

                if (isResolved.HasValue)
                    query = query.Where(h => h.IsResolved == isResolved.Value);

                return query.ToList();
            }
        }

        public void ClearHistory()
        {
            lock (_lockObject)
            {
                _history.Clear();
                HistoryCleared?.Invoke(this, EventArgs.Empty);
                _ = SaveHistoryAsync();
            }
        }

        public void ClearOldEntries(int maxDays)
        {
            var cutoffDate = DateTime.Now.AddDays(-maxDays);
            lock (_lockObject)
            {
                var entriesToRemove = _history.Where(h => h.Timestamp < cutoffDate).ToList();
                foreach (var entry in entriesToRemove)
                {
                    _history.Remove(entry);
                }
                
                if (entriesToRemove.Any())
                {
                    _ = SaveHistoryAsync();
                }
            }
        }

        public async Task SaveHistoryAsync()
        {
            try
            {
                List<ThreatHistoryEntry> historySnapshot;
                lock (_lockObject)
                {
                    historySnapshot = _history.ToList();
                }

                var json = JsonConvert.SerializeObject(historySnapshot, Formatting.Indented);
                await File.WriteAllTextAsync(HistoryFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving threat history: {ex.Message}");
            }
        }

        public void LoadHistory()
        {
            try
            {
                if (File.Exists(HistoryFilePath))
                {
                    var json = File.ReadAllText(HistoryFilePath);
                    var entries = JsonConvert.DeserializeObject<List<ThreatHistoryEntry>>(json);
                    
                    if (entries != null)
                    {
                        lock (_lockObject)
                        {
                            _history.Clear();
                            foreach (var entry in entries.OrderByDescending(e => e.Timestamp))
                            {
                                _history.Add(entry);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading threat history: {ex.Message}");
            }
        }

        public async Task ExportHistoryAsync(string filePath, DateTime? fromDate = null, DateTime? toDate = null)
        {
            try
            {
                var entries = GetFilteredHistory(fromDate: fromDate, toDate: toDate);
                var json = JsonConvert.SerializeObject(entries, Formatting.Indented);
                await File.WriteAllTextAsync(filePath, json);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to export history: {ex.Message}");
            }
        }

        // Helper methods
        private ThreatSeverity GetSeverityFromDetection(ScanResult scanResult)
        {
            if (scanResult.DetectionCount == 0)
                return ThreatSeverity.Info;
            
            var detectionRatio = (double)scanResult.DetectionCount / scanResult.TotalScans;
            
            return detectionRatio switch
            {
                >= 0.5 => ThreatSeverity.Critical,
                >= 0.3 => ThreatSeverity.High,
                >= 0.1 => ThreatSeverity.Medium,
                > 0 => ThreatSeverity.Low,
                _ => ThreatSeverity.Info
            };
        }

        private ThreatSeverity GetSeverityFromThreatLevel(string threatLevel)
        {
            return threatLevel?.ToLower() switch
            {
                "critical" => ThreatSeverity.Critical,
                "high" => ThreatSeverity.High,
                "medium" => ThreatSeverity.Medium,
                "low" => ThreatSeverity.Low,
                "safe" => ThreatSeverity.Info,
                _ => ThreatSeverity.Info
            };
        }

        // Statistics methods
        public Dictionary<string, int> GetEventTypeStatistics(int days = 30)
        {
            var cutoffDate = DateTime.Now.AddDays(-days);
            lock (_lockObject)
            {
                return _history
                    .Where(h => h.Timestamp >= cutoffDate)
                    .GroupBy(h => h.EventType)
                    .ToDictionary(g => g.Key.ToString(), g => g.Count());
            }
        }

        public Dictionary<string, int> GetSeverityStatistics(int days = 30)
        {
            var cutoffDate = DateTime.Now.AddDays(-days);
            lock (_lockObject)
            {
                return _history
                    .Where(h => h.Timestamp >= cutoffDate)
                    .GroupBy(h => h.Severity)
                    .ToDictionary(g => g.Key.ToString(), g => g.Count());
            }
        }
    }
}
