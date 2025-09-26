never remove main files like MainWindow.xaml and MainWindow.xaml.cs, make changes to make it work and only work on backend logic in /Services and /Models


# GitHub Copilot Instructions for KeyGuard Pro

This document provides strict, role-specific instructions for developing the KeyGuard Pro application. Adhere to these rules to ensure code quality, consistency, and efficiency.

## 🔴 Core Directives & Rules 🔴

1.  *🛑 CRITICAL: DO NOT DELETE OR REPLACE CORE FILES.* You are strictly forbidden from deleting, moving, renaming, or recreating the MainWindow.xaml and MainWindow.xaml.cs files. Your task is to *modify and edit the code within the existing files*. Replacing these files is inefficient, reintroduces old errors, and must be avoided at all costs.

2.  *CURRENT FOCUS: FILE SCANNER UI & BACKEND.* Focus on improving the file scanner section with:
   - ✅ Enhanced UI for folder selection and scanning progress
   - ✅ Real-time progress tracking with accurate percentage and file display
   - ✅ Full VirusTotal API integration for comprehensive malware detection
   - ✅ Professional scanning animations and status updates
   - ✅ Live file scanning display with animations
   - ✅ Proper folder selection UI feedback
   - ✅ Functional progress bar with accurate percentage
   - ✅ Real-time scanning status with file-by-file updates

3.  *PRIORITIZE MODIFYING EXISTING FILES.* Before creating a new file, you *MUST* utilize the existing backend structure. Implement logic within the established service and model classes.

4.  *IMPLEMENT REAL-TIME FUNCTIONALITY.* All backend services must work with live, real-time system data. The ProcessScanner must return currently running processes, not a cached or dummy list.

## Key Implementation Patterns

-   *Responsiveness*: Heavy operations (process scanning, WMI queries, file scanning) must be designed to run asynchronously.
-   *Error Handling*: Wrap calls that can fail due to permissions (e.g., accessing process.MainModule or killing a protected process) in try-catch blocks.
-   *Progress Tracking*: Implement accurate progress reporting for file scanning with real-time updates.
-   *VirusTotal Integration*: Use free VirusTotal API for comprehensive malware detection and analysis.

## Key Backend Files

-   /Models/ProcessInfo.cs: The base data model for a single process.
-   /Models/ProcessNodeViewModel.cs: The hierarchical model for the process tree.
-   /Models/ScanResult.cs: The data model for file scan results with threat analysis.
-   /Services/ProcessScanner.cs: Logic for fetching, categorizing, and building the process tree.
-   /Services/FileScannerService.cs: *(Primary Focus)* Logic for file scanning, VirusTotal integration, and progress tracking.
-   /Services/ThreatDetector.cs: Logic for analyzing a process and assigning a threat level.
-   /Services/ProcessController.cs: Logic for safely terminating a process.
-   /Services/DatabaseManager.cs: Logic for all SQLite database interactions.

## ✅ FILE SCANNER IMPLEMENTATION COMPLETE

### Phase 1: UI Improvements ✅
- ✅ **Enhanced Select Folder Button**: Larger, more professional design with better spacing
- ✅ **Fixed Folder Display**: Now shows selected folder path correctly instead of "No folder selected"
- ✅ **Improved Button Layout**: Better Start/Cancel scan button management with visibility control

### Phase 2: Backend Services ✅
- ✅ **Complete VirusTotal Service**: Full API integration with rate limiting, hash calculations, and error handling
- ✅ **Advanced FileScannerService**: Real-time scanning with progress reporting and comprehensive threat detection
- ✅ **Enhanced ThreatDetector**: File-based analysis with heuristic detection for various threat levels

### Phase 3: Real-time Features ✅
- ✅ **Accurate Progress Bar**: Shows 0-100% progress with real-time updates during scanning
- ✅ **Live File Display**: Shows currently scanning file with proper animations
- ✅ **Real-time Status Updates**: Comprehensive status messages and file count tracking
- ✅ **Professional Animations**: Smooth UI transitions and scanning state management

### Phase 4: Advanced Features ✅
- ✅ **Functional Cancel**: Proper scan cancellation with UI state management
- ✅ **Detailed Results**: Comprehensive scan results with threat analysis and detection ratios
- ✅ **Summary Statistics**: Complete scan summary with file counts, threats, and duration
- ✅ **Professional UX**: Error handling, notifications, and user feedback

### Key Features Implemented:
1. **Professional UI**: Large, well-styled buttons and clear status displays
2. **Real Progress Tracking**: Accurate percentage and file-by-file progress
3. **VirusTotal Integration**: Full API support with intelligent rate limiting
4. **Live Scanning Display**: Shows current file being scanned with animations
5. **Comprehensive Results**: Detailed threat analysis and scan summaries
6. **Proper State Management**: Clean UI transitions and cancellation support
7. **Error Handling**: Robust error management with user notifications

### Technical Implementation:
- **FileScannerService**: Event-driven architecture with progress reporting
- **VirusTotal API**: Complete integration with hash calculation and analysis
- **UI Integration**: Proper XAML binding with real-time updates
- **Threat Detection**: Multi-level analysis with heuristic and API scanning