using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KeyloggerDetector.Models;

namespace KeyloggerDetector.Services
{
    public class VirusTotalService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private readonly SemaphoreSlim _rateLimitSemaphore;
        private DateTime _lastApiCall = DateTime.MinValue;
        private const int MIN_API_INTERVAL_MS = 15000; // 15 seconds between calls for free API

        public VirusTotalService(string apiKey)
        {
            _apiKey = apiKey;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            _rateLimitSemaphore = new SemaphoreSlim(1, 1);
        }

        public async Task<VirusTotalScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrEmpty(_apiKey))
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "VirusTotal API key not configured"
                    };
                }

                // Calculate file hash
                var fileHash = CalculateFileHash(filePath);
                if (string.IsNullOrEmpty(fileHash))
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Failed to calculate file hash"
                    };
                }

                // Check rate limit
                await EnforceRateLimit(cancellationToken);

                // Check if file already exists in VirusTotal database
                var existingResult = await GetFileReportAsync(fileHash, cancellationToken);
                if (existingResult.IsSuccess)
                {
                    return existingResult;
                }

                // If file doesn't exist, upload it for scanning
                var uploadResult = await UploadFileAsync(filePath, cancellationToken);
                if (!uploadResult.IsSuccess)
                {
                    return uploadResult;
                }

                // Wait a bit for initial analysis
                await Task.Delay(5000, cancellationToken);

                // Get the analysis result
                return await GetFileReportAsync(fileHash, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return new VirusTotalScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Scan was cancelled"
                };
            }
            catch (Exception ex)
            {
                return new VirusTotalScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = $"VirusTotal scan error: {ex.Message}"
                };
            }
        }

        private async Task<VirusTotalScanResult> GetFileReportAsync(string fileHash, CancellationToken cancellationToken)
        {
            try
            {
                await EnforceRateLimit(cancellationToken);

                var response = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{fileHash}", cancellationToken);
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return ParseVirusTotalResponse(content);
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "File not found in VirusTotal database"
                    };
                }
                else
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"VirusTotal API error: {response.StatusCode}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new VirusTotalScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = $"API request failed: {ex.Message}"
                };
            }
        }

        private async Task<VirusTotalScanResult> UploadFileAsync(string filePath, CancellationToken cancellationToken)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 32 * 1024 * 1024) // 32MB limit for free API
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "File too large for VirusTotal upload (max 32MB)"
                    };
                }

                await EnforceRateLimit(cancellationToken);

                using var form = new MultipartFormDataContent();
                using var fileStream = File.OpenRead(filePath);
                using var fileContent = new StreamContent(fileStream);
                
                form.Add(fileContent, "file", Path.GetFileName(filePath));

                var response = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/files", form, cancellationToken);
                
                if (response.IsSuccessStatusCode)
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = true,
                        DetectionCount = 0,
                        TotalScans = 0,
                        ThreatNames = new List<string>(),
                        ScanDate = DateTime.Now
                    };
                }
                else
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"File upload failed: {response.StatusCode}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new VirusTotalScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = $"Upload error: {ex.Message}"
                };
            }
        }

        private VirusTotalScanResult ParseVirusTotalResponse(string jsonResponse)
        {
            try
            {
                using var document = JsonDocument.Parse(jsonResponse);
                var root = document.RootElement;
                
                if (!root.TryGetProperty("data", out var data))
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid VirusTotal response format"
                    };
                }

                if (!data.TryGetProperty("attributes", out var attributes))
                {
                    return new VirusTotalScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Missing attributes in VirusTotal response"
                    };
                }

                var threatNames = new List<string>();
                var detectionCount = 0;
                var totalScans = 0;

                if (attributes.TryGetProperty("last_analysis_results", out var results))
                {
                    foreach (var result in results.EnumerateObject())
                    {
                        totalScans++;
                        if (result.Value.TryGetProperty("category", out var category))
                        {
                            var categoryValue = category.GetString();
                            if (categoryValue == "malicious" || categoryValue == "suspicious")
                            {
                                detectionCount++;
                                if (result.Value.TryGetProperty("result", out var resultName))
                                {
                                    var threat = resultName.GetString();
                                    if (!string.IsNullOrEmpty(threat))
                                    {
                                        threatNames.Add($"{result.Name}: {threat}");
                                    }
                                }
                            }
                        }
                    }
                }

                return new VirusTotalScanResult
                {
                    IsSuccess = true,
                    DetectionCount = detectionCount,
                    TotalScans = totalScans,
                    ThreatNames = threatNames,
                    ScanDate = DateTime.Now
                };
            }
            catch (Exception ex)
            {
                return new VirusTotalScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = $"Failed to parse VirusTotal response: {ex.Message}"
                };
            }
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        private async Task EnforceRateLimit(CancellationToken cancellationToken)
        {
            await _rateLimitSemaphore.WaitAsync(cancellationToken);
            try
            {
                var timeSinceLastCall = DateTime.Now - _lastApiCall;
                if (timeSinceLastCall.TotalMilliseconds < MIN_API_INTERVAL_MS)
                {
                    var delay = MIN_API_INTERVAL_MS - (int)timeSinceLastCall.TotalMilliseconds;
                    await Task.Delay(delay, cancellationToken);
                }
                _lastApiCall = DateTime.Now;
            }
            finally
            {
                _rateLimitSemaphore.Release();
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore?.Dispose();
        }
    }

    public class VirusTotalScanResult
    {
        public bool IsSuccess { get; set; }
        public string ErrorMessage { get; set; }
        public int DetectionCount { get; set; }
        public int TotalScans { get; set; }
        public List<string> ThreatNames { get; set; } = new List<string>();
        public DateTime ScanDate { get; set; }
        
        public bool IsMalicious => IsSuccess && DetectionCount > 0;
        public string DetectionRatio => IsSuccess ? $"{DetectionCount}/{TotalScans}" : "Error";
    }
}
