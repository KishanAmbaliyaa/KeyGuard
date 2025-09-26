using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KeyloggerDetector.Models;

namespace KeyloggerDetector.Services
{
    public class FileScannerService
    {
        private readonly VirusTotalService _virusTotalService;
        private readonly ThreatDetector _threatDetector;
        
        public event EventHandler<ScanProgressEventArgs> ProgressChanged;
        public event EventHandler<FileScannedEventArgs> FileScanned;
        public event EventHandler<ScanCompletedEventArgs> ScanCompleted;

        public FileScannerService(string virusTotalApiKey = null)
        {
            _virusTotalService = !string.IsNullOrEmpty(virusTotalApiKey) 
                ? new VirusTotalService(virusTotalApiKey) 
                : null;
            _threatDetector = new ThreatDetector();
        }

        public async Task<List<ScanResult>> ScanFolderAsync(string folderPath, bool includeSubfolders = true, bool useVirusTotal = true, CancellationToken cancellationToken = default)
        {
            var results = new List<ScanResult>();
            var startTime = DateTime.Now;

            try
            {
                // Get all files to scan
                var files = GetFilesToScan(folderPath, includeSubfolders);
                var totalFiles = files.Count;

                if (totalFiles == 0)
                {
                    OnScanCompleted(new ScanCompletedEventArgs
                    {
                        Results = results,
                        TotalFiles = 0,
                        Duration = DateTime.Now - startTime,
                        WasCancelled = false
                    });
                    return results;
                }

                // Report initial progress
                OnProgressChanged(new ScanProgressEventArgs
                {
                    FilesScanned = 0,
                    TotalFiles = totalFiles,
                    CurrentFile = "Initializing scan...",
                    PercentComplete = 0
                });

                // Scan each file
                for (int i = 0; i < files.Count; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        OnScanCompleted(new ScanCompletedEventArgs
                        {
                            Results = results,
                            TotalFiles = totalFiles,
                            Duration = DateTime.Now - startTime,
                            WasCancelled = true
                        });
                        return results;
                    }

                    var file = files[i];
                    var progress = (int)((double)(i + 1) / totalFiles * 100);

                    // Update progress
                    OnProgressChanged(new ScanProgressEventArgs
                    {
                        FilesScanned = i,
                        TotalFiles = totalFiles,
                        CurrentFile = Path.GetFileName(file),
                        PercentComplete = progress
                    });

                    // Scan the file
                    var scanResult = await ScanFileAsync(file, useVirusTotal && _virusTotalService != null, cancellationToken);
                    results.Add(scanResult);

                    // Report file scanned
                    OnFileScanned(new FileScannedEventArgs
                    {
                        Result = scanResult,
                        FilesScanned = i + 1,
                        TotalFiles = totalFiles
                    });

                    // Small delay to allow UI updates
                    await Task.Delay(50, cancellationToken);
                }

                // Report completion
                OnScanCompleted(new ScanCompletedEventArgs
                {
                    Results = results,
                    TotalFiles = totalFiles,
                    Duration = DateTime.Now - startTime,
                    WasCancelled = false
                });

                return results;
            }
            catch (OperationCanceledException)
            {
                OnScanCompleted(new ScanCompletedEventArgs
                {
                    Results = results,
                    TotalFiles = results.Count,
                    Duration = DateTime.Now - startTime,
                    WasCancelled = true
                });
                return results;
            }
            catch (Exception ex)
            {
                OnScanCompleted(new ScanCompletedEventArgs
                {
                    Results = results,
                    TotalFiles = results.Count,
                    Duration = DateTime.Now - startTime,
                    WasCancelled = false,
                    Error = ex.Message
                });
                return results;
            }
        }

        private async Task<ScanResult> ScanFileAsync(string filePath, bool useVirusTotal, CancellationToken cancellationToken)
        {
            var scanResult = new ScanResult
            {
                FileName = Path.GetFileName(filePath),
                FilePath = filePath,
                ScanDate = DateTime.Now,
                Status = "Scanning..."
            };

            try
            {
                // Get file info
                var fileInfo = new FileInfo(filePath);
                scanResult.FileSize = fileInfo.Length;

                // Perform local threat detection first
                var localThreatLevel = _threatDetector.AnalyzeFile(filePath);
                var isLocalThreat = localThreatLevel > ThreatLevel.Low;

                if (useVirusTotal && _virusTotalService != null)
                {
                    // Scan with VirusTotal
                    var vtResult = await _virusTotalService.ScanFileAsync(filePath, cancellationToken);
                    
                    if (vtResult.IsSuccess)
                    {
                        scanResult.DetectionCount = vtResult.DetectionCount;
                        scanResult.TotalScans = vtResult.TotalScans;
                        scanResult.ThreatNames = vtResult.ThreatNames;
                        scanResult.IsMalicious = vtResult.IsMalicious || isLocalThreat;
                        scanResult.Status = vtResult.IsMalicious ? "Malicious" : isLocalThreat ? "Suspicious" : "Clean";
                    }
                    else
                    {
                        // VirusTotal failed, use local detection only
                        scanResult.IsMalicious = isLocalThreat;
                        scanResult.Status = isLocalThreat ? "Suspicious (Local)" : "Clean (Local)";
                        scanResult.DetectionCount = isLocalThreat ? 1 : 0;
                        scanResult.TotalScans = 1;
                        
                        if (isLocalThreat)
                        {
                            scanResult.ThreatNames = new List<string> { "Local heuristic detection" };
                        }
                    }
                }
                else
                {
                    // Local scanning only
                    scanResult.IsMalicious = isLocalThreat;
                    scanResult.Status = isLocalThreat ? "Suspicious" : "Clean";
                    scanResult.DetectionCount = isLocalThreat ? 1 : 0;
                    scanResult.TotalScans = 1;
                    
                    if (isLocalThreat)
                    {
                        scanResult.ThreatNames = new List<string> { GetThreatDescription(localThreatLevel) };
                    }
                }

                // Calculate hashes for important files
                if (scanResult.IsMalicious || fileInfo.Length < 10 * 1024 * 1024) // Files under 10MB
                {
                    try
                    {
                        scanResult.MD5Hash = CalculateFileHash(filePath, "MD5");
                        scanResult.SHA256Hash = CalculateFileHash(filePath, "SHA256");
                    }
                    catch
                    {
                        // Hash calculation failed, continue without hashes
                    }
                }
            }
            catch (Exception ex)
            {
                scanResult.Status = "Error";
                scanResult.IsMalicious = false;
                scanResult.ThreatNames = new List<string> { $"Scan error: {ex.Message}" };
            }

            return scanResult;
        }

        private List<string> GetFilesToScan(string folderPath, bool includeSubfolders)
        {
            var files = new List<string>();
            
            try
            {
                var searchOption = includeSubfolders ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                
                // Get all files with common executable and document extensions
                var extensions = new[] { "*.exe", "*.dll", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", 
                                       "*.jar", "*.com", "*.scr", "*.pif", "*.msi", "*.zip", "*.rar",
                                       "*.doc", "*.docx", "*.xls", "*.xlsx", "*.pdf", "*.rtf" };

                foreach (var extension in extensions)
                {
                    try
                    {
                        var matchingFiles = Directory.GetFiles(folderPath, extension, searchOption);
                        files.AddRange(matchingFiles);
                    }
                    catch (Exception)
                    {
                        // Skip directories we can't access
                        continue;
                    }
                }
            }
            catch (Exception)
            {
                // Return empty list if we can't access the folder
            }

            return files.Distinct().OrderBy(f => f).ToList();
        }

        private string GetThreatDescription(ThreatLevel threatLevel)
        {
            return threatLevel switch
            {
                ThreatLevel.Critical => "Critical threat detected",
                ThreatLevel.High => "High risk file detected",
                ThreatLevel.Medium => "Medium risk file detected",
                ThreatLevel.Low => "Low risk file detected",
                _ => "Unknown threat level"
            };
        }

        private string CalculateFileHash(string filePath, string algorithm)
        {
            using var stream = File.OpenRead(filePath);
            
            return algorithm.ToUpper() switch
            {
                "MD5" => CalculateMD5(stream),
                "SHA256" => CalculateSHA256(stream),
                _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithm}")
            };
        }

        private string CalculateMD5(Stream stream)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var hash = md5.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private string CalculateSHA256(Stream stream)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        protected virtual void OnProgressChanged(ScanProgressEventArgs e)
        {
            ProgressChanged?.Invoke(this, e);
        }

        protected virtual void OnFileScanned(FileScannedEventArgs e)
        {
            FileScanned?.Invoke(this, e);
        }

        protected virtual void OnScanCompleted(ScanCompletedEventArgs e)
        {
            ScanCompleted?.Invoke(this, e);
        }

        public void Dispose()
        {
            _virusTotalService?.Dispose();
        }
    }

    public class ScanProgressEventArgs : EventArgs
    {
        public int FilesScanned { get; set; }
        public int TotalFiles { get; set; }
        public string CurrentFile { get; set; }
        public int PercentComplete { get; set; }
    }

    public class FileScannedEventArgs : EventArgs
    {
        public ScanResult Result { get; set; }
        public int FilesScanned { get; set; }
        public int TotalFiles { get; set; }
    }

    public class ScanCompletedEventArgs : EventArgs
    {
        public List<ScanResult> Results { get; set; }
        public int TotalFiles { get; set; }
        public TimeSpan Duration { get; set; }
        public bool WasCancelled { get; set; }
        public string Error { get; set; }
    }
}
