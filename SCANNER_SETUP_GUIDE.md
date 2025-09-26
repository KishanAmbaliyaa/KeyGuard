# KeyGuard Pro - File Scanner Setup Guide

## Overview

KeyGuard Pro now includes a powerful file scanner that can detect keyloggers, malware, and suspicious files using both local analysis and online threat intelligence.

## Features

✅ **Local Analysis**
- Suspicious file extension detection
- Keylogger signature scanning
- File size anomaly detection
- System directory monitoring
- Extension masquerading detection

✅ **Online Threat Intelligence** (Optional)
- VirusTotal API integration
- Real-time malware database checking
- Community-driven threat detection
- Hash-based file reputation

✅ **Real-time Scanning**
- Live progress updates
- Instant threat notifications
- Comprehensive scan results
- Detailed threat analysis

## Quick Start

1. **Launch KeyGuard Pro**
2. **Navigate to Scanner Tab**
3. **Click "Select Folder"** to choose directory to scan
4. **Click "START SCAN"** to begin analysis
5. **Review Results** in the results table

## VirusTotal API Setup (Optional but Recommended)

To enable enhanced malware detection with VirusTotal:

### Step 1: Get Free API Key
1. Visit [VirusTotal.com](https://www.virustotal.com)
2. Create a free account
3. Go to your profile → API Key
4. Copy your free API key

### Step 2: Configure API Key
1. Open `Services/FileScannerService.cs`
2. Find the line: `private static string VIRUSTOTAL_API_KEY = "your_free_api_key_here";`
3. Replace `"your_free_api_key_here"` with your actual API key
4. Save the file and rebuild the project

### API Rate Limits (Free Account)
- **4 requests per minute**
- **500 requests per day**
- **500 requests per month**

The scanner automatically handles rate limiting with 15-second delays between requests.

## Local Scanning (No API Required)

Even without VirusTotal API, the scanner provides comprehensive local analysis:

- **Suspicious Extensions**: .exe, .bat, .cmd, .scr, .vbs, .js, .dll, .sys
- **Keylogger Keywords**: keylog, keystroke, password, credential, stealer, logger
- **Size Anomalies**: Files larger than 50MB flagged
- **Location Analysis**: System directory monitoring
- **Extension Masquerading**: Executables disguised as documents

## Understanding Results

### Scan Results Columns

| Column | Description |
|--------|-------------|
| **File Name** | Name of the scanned file |
| **Status** | Scan status (Clean, Threats Detected, Error) |
| **Detection** | Threat ratio (e.g., "3/67" = 3 engines detected threats out of 67) |
| **Threats** | List of detected threat names |
| **Size** | File size in human-readable format |
| **Path** | Full file path |

### Threat Levels

- 🟢 **Clean**: No threats detected
- 🟡 **Suspicious**: Local analysis flagged potential issues
- 🔴 **Malicious**: Multiple engines detected threats

## Performance Tips

1. **Scan Specific Folders**: Avoid scanning entire drives
2. **Use Subfolders Option**: Enable/disable based on need
3. **Monitor Progress**: Watch real-time updates in capture history
4. **API Usage**: Monitor your VirusTotal quota

## Common Scan Locations

For quick security checks, consider scanning:

- `%USERPROFILE%\\Downloads` - Downloaded files
- `%APPDATA%` - Application data
- `%TEMP%` - Temporary files
- `%USERPROFILE%\\Desktop` - Desktop files
- `C:\\Windows\\Temp` - System temp files

## Troubleshooting

### "No folder selected" error
- Click "Select Folder" before starting scan

### API errors
- Check your API key is correct
- Verify internet connection
- Ensure you haven't exceeded rate limits

### Scan takes too long
- Scan smaller directories
- Check if API rate limiting is causing delays
- Consider scanning without VirusTotal for faster results

### False positives
- Some legitimate software may be flagged
- Cross-reference results with multiple sources
- Check file reputation on VirusTotal website

## Security Notes

⚠️ **Important Warnings**

1. **Quarantine Suspected Files**: Don't execute files flagged as malicious
2. **Backup Important Data**: Before removing suspected files
3. **Professional Analysis**: For critical systems, consult security professionals
4. **Keep Updated**: Regularly update the scanner and threat definitions

## Support

For issues or questions:
1. Check the capture history for detailed error messages
2. Verify all setup steps were completed correctly
3. Ensure you have proper permissions for scanned directories

---

**KeyGuard Pro** - Advanced Security Monitoring and Threat Detection
