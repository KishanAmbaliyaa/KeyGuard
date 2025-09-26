using System;
using System.IO;
using System.Threading.Tasks;
using KeyloggerDetector.Models;
using Newtonsoft.Json;

namespace KeyloggerDetector.Services
{
    public class SettingsService
    {
        private static readonly string SettingsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "KeyGuardPro",
            "settings.json"
        );

        private AppSettings _currentSettings;
        
        public event EventHandler<AppSettings> SettingsChanged;

        public AppSettings CurrentSettings
        {
            get => _currentSettings ??= LoadSettings();
            private set
            {
                _currentSettings = value;
                SettingsChanged?.Invoke(this, value);
            }
        }

        public SettingsService()
        {
            // Ensure the settings directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsFilePath));
        }

        public AppSettings LoadSettings()
        {
            try
            {
                if (File.Exists(SettingsFilePath))
                {
                    var json = File.ReadAllText(SettingsFilePath);
                    var settings = JsonConvert.DeserializeObject<AppSettings>(json);
                    
                    if (settings != null)
                    {
                        CurrentSettings = settings;
                        return settings;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading settings: {ex.Message}");
            }

            // Return default settings if loading fails
            var defaultSettings = new AppSettings();
            CurrentSettings = defaultSettings;
            return defaultSettings;
        }

        public async Task SaveSettingsAsync(AppSettings settings)
        {
            try
            {
                var json = JsonConvert.SerializeObject(settings, Formatting.Indented);
                await File.WriteAllTextAsync(SettingsFilePath, json);
                CurrentSettings = settings;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving settings: {ex.Message}");
                throw;
            }
        }

        public void SaveSettings(AppSettings settings)
        {
            try
            {
                var json = JsonConvert.SerializeObject(settings, Formatting.Indented);
                File.WriteAllText(SettingsFilePath, json);
                CurrentSettings = settings;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving settings: {ex.Message}");
                throw;
            }
        }

        public void ResetToDefaults()
        {
            var defaultSettings = new AppSettings();
            SaveSettings(defaultSettings);
        }

        public bool ValidateVirusTotalApiKey(string apiKey)
        {
            // Basic validation - should be 64 characters long and alphanumeric
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Remove any whitespace
            apiKey = apiKey.Trim();

            // Check length (VirusTotal API keys are typically 64 characters)
            if (apiKey.Length != 64)
                return false;

            // Check if it's alphanumeric
            foreach (char c in apiKey)
            {
                if (!char.IsLetterOrDigit(c))
                    return false;
            }

            return true;
        }

        public string GetSettingsFilePath()
        {
            return SettingsFilePath;
        }

        public bool BackupSettings(string backupPath)
        {
            try
            {
                if (File.Exists(SettingsFilePath))
                {
                    File.Copy(SettingsFilePath, backupPath, true);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public bool RestoreSettings(string backupPath)
        {
            try
            {
                if (File.Exists(backupPath))
                {
                    File.Copy(backupPath, SettingsFilePath, true);
                    LoadSettings(); // Reload the restored settings
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
