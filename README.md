# KeyGuard Pro - Advanced Keylogger Detection System

A comprehensive Windows desktop application for detecting and monitoring malicious keylogger software through advanced system analysis, AI-powered threat detection, real-time monitoring, and user control features in a modern dark-themed interface.

## 🛡️ Core Features

### 🔍 Advanced Scanner
- **Circular Progress Interface**: Modern animated scanning interface with real-time progress indication
- **AI-Powered Detection**: Intelligent threat analysis using rule-based machine learning algorithms
- **Comprehensive Process Analysis**: Deep inspection of all running processes and their behaviors
- **Real-time Threat Scoring**: Dynamic threat level assessment (Safe, Low, Medium, High, Critical)
- **Automated Notifications**: Instant alerts for detected security threats

### ⚙️ Process Monitor
- **Complete Process Visibility**: List all foreground and background processes with detailed metadata
- **Keyboard Hook Detection**: Real-time detection of processes accessing keyboard input streams
- **Resource Access Monitoring**: Track microphone, camera, and system resource access patterns
- **Safe Process Termination**: Intelligent process control with system protection safeguards
- **Advanced Filtering**: Search and filter processes by name, PID, or threat characteristics

### 🎮 Input Monitoring Playground
- **Secure Testing Environment**: Safe area for testing keyboard input monitoring behavior
- **Global Input Tracking**: System-wide keyboard hook detection and process identification
- **Real-time Capture Display**: Live visualization of which processes receive keyboard input
- **Historical Monitoring Log**: Persistent record of input capture events with timestamps
- **Toggle-based Control**: Easy start/stop monitoring with visual status indicators

### � Threat Detection Engine
- **Multi-layered Analysis**: Combines process name analysis, behavioral patterns, and resource usage
- **Behavioral Pattern Recognition**: Identifies suspicious activities characteristic of keyloggers
- **Location-based Risk Assessment**: Evaluates executable locations for security risks
- **System Access Pattern Analysis**: Monitors unusual system API calls and hooks
- **Dynamic Threat Scoring**: Real-time risk calculation with automatic severity classification

### 🎨 Modern User Interface
- **Dark Theme Design**: Professional dark interface with red/orange accent colors
- **Circular Scanner**: Animated progress ring with percentage display and control buttons
- **Navigation Sidebar**: Icon-based navigation between Scanner, Process Monitor, Playground, and History
- **Custom Window Frame**: Borderless window with custom title bar and window controls
- **Responsive Layout**: Adaptive interface that works across different screen sizes

## 🔧 Technical Architecture

### Technology Stack
- **Framework**: .NET 9 with WPF for modern Windows desktop development
- **UI Technology**: WPF with custom dark theme and Fluent Design principles
- **Security APIs**: Windows Management Instrumentation (WMI) for system monitoring
- **Keyboard Monitoring**: Low-level keyboard hooks via user32.dll SetWindowsHookEx API
- **Database**: SQLite for persistent logging and threat history storage
- **Process Control**: Advanced Windows Process API integration with safety mechanisms

### AI & Detection Algorithms
- **Rule-based ML**: Sophisticated scoring algorithms inspired by machine learning principles
- **Pattern Recognition**: Multi-factor analysis including process names, locations, and behaviors
- **Behavioral Analysis**: Real-time assessment of process activities and system interactions
- **Threat Classification**: Five-tier threat level system with automatic severity determination
- **False Positive Reduction**: Intelligent filtering to minimize alerts for legitimate software

### Security & Privacy
- **Local Processing**: All analysis performed locally on your machine - no data transmission
- **Administrator Privileges**: Secure elevation for system-wide process access and control
- **Safe Termination**: Protected termination with critical system process safeguards
- **Audit Trail**: Comprehensive logging of all actions and detected threats
- **No Data Collection**: Application does not store or transmit any typed content

## 📋 System Requirements

- **Operating System**: Windows 10 version 1809 (build 17763) or later / Windows 11
- **Framework**: .NET 9 SDK (automatically included in distribution)
- **Privileges**: Administrator access required for system monitoring capabilities
- **Memory**: Minimum 4GB RAM (8GB recommended for optimal performance)
- **Storage**: 50MB free disk space for application and database files

## 🚀 Installation & Setup

### Quick Start (Recommended)
1. **Download**: Get the latest KeyGuard Pro release from the repository
2. **Extract**: Unzip the application files to your preferred location
3. **Launch**: Double-click `LaunchKeyGuardPro.bat` for easy startup with admin privileges
4. **Grant Permissions**: Allow UAC elevation prompt for system access
5. **Start Scanning**: Click the "START SCAN" button in the main interface

### Manual Launch Options
1. **Release Version**: Right-click `Release\KeyloggerDetector.exe` → "Run as administrator"
2. **Development Version**: Run `dotnet run KeyloggerDetector.csproj` in elevated PowerShell
3. **Batch Helper**: Use `RunAsAdmin.bat` for automated admin privilege elevation

### Development Setup
1. **Install .NET 9 SDK**:
   ```powershell
   # Download from: https://dotnet.microsoft.com/download/dotnet/9.0
   # Choose "SDK" version for development
   ```

2. **Clone and Build**:
   ```powershell
   git clone <repository-url>
   cd KeyloggerDetector
   dotnet restore
   dotnet build KeyloggerDetector.csproj
   ```

3. **Create Release Build**:
   ```powershell
   dotnet publish KeyloggerDetector.csproj -c Release -o Release --self-contained true -r win-x64
   ```

4. **Run in Development**:
   ```powershell
   # Start PowerShell as Administrator
   dotnet run KeyloggerDetector.csproj
   ```

## 📖 Usage Guide

### 🔍 Scanner Tab
1. **Initiate Scan**: Click the central "START SCAN" button to begin system analysis
2. **Monitor Progress**: Watch the circular progress ring and percentage indicator
3. **Review Results**: Examine detected threats in the results area below the scanner
4. **Take Action**: Click on threat items to view details and available actions

### ⚙️ Process Monitor Tab
1. **View Processes**: Navigate to Process Monitor to see all running processes
2. **Search & Filter**: Use the search box to find specific processes by name or PID
3. **Analyze Threats**: Review the Threat Level column for security assessment
4. **Terminate Processes**: Use the Terminate button for suspicious processes (with safety checks)

### 🎮 Playground Tab
1. **Start Monitoring**: Click "Start Global Monitoring" to begin input tracking
2. **Test Input**: Type in the secure text area to see input capture behavior
3. **Monitor Results**: Watch the real-time display showing which process captures input
4. **Review History**: Check the monitoring history for patterns and suspicious activity

### 📊 Advanced Features
- **Threat History**: Review past scans and detected threats in the History tab
- **Settings**: Customize application behavior in the Settings tab
- **Database Logs**: All actions and threats are automatically logged to SQLite database
- **Export Results**: Generate reports of scanning results and threat assessments

## 🛡️ Security Features

### Threat Detection Capabilities
- **Keyboard Hook Detection**: Identifies processes using SetWindowsHookEx with WH_KEYBOARD_LL
- **Suspicious Process Analysis**: Evaluates process names, locations, and execution patterns
- **Resource Access Monitoring**: Tracks unusual access to input devices and system resources
- **Behavioral Pattern Recognition**: Identifies characteristic keylogger behaviors and signatures
- **System API Monitoring**: Detects unusual Win32 API calls related to input capture

### Safety Mechanisms
- **Critical Process Protection**: Prevents termination of essential Windows system processes
- **Graceful Termination**: Attempts safe process shutdown before forced termination
- **Backup & Recovery**: Maintains logs for potential system recovery if needed
- **User Confirmation**: Requires explicit confirmation before taking destructive actions
- **Real-time Validation**: Continuous verification of process states before actions

## 🔍 Advanced Detection Algorithms

### Multi-Factor Threat Analysis
KeyGuard Pro employs sophisticated detection mechanisms:

1. **Process Name Analysis** (50 points): Scans for keywords associated with keyloggers
2. **Keyboard Hook Detection** (30 points): Identifies low-level keyboard monitoring
3. **System Access Patterns** (20 points): Evaluates unusual system resource access
4. **Behavioral Analysis** (25 points): Assesses suspicious process behaviors
5. **Location Assessment** (15 points): Checks for execution from suspicious directories
6. **Signature Analysis** (10 points): Validates process descriptions and metadata

### Threat Level Classification
- **Critical (80+ points)**: Immediate threat requiring urgent action
- **High (60-79 points)**: Serious security concern requiring investigation
- **Medium (35-59 points)**: Potentially unwanted behavior worth monitoring
- **Low (15-34 points)**: Minor security consideration for awareness
- **Safe (0-14 points)**: Normal process with no detected security concerns

## 📊 Database & Logging

### Persistent Storage
KeyGuard Pro maintains comprehensive logs in SQLite database:
- **Scan History**: Records of all system scans with timestamps and results
- **Threat Log**: Detailed records of all detected threats with severity levels
- **Action Log**: Complete audit trail of all user actions and system responses

### Database Location
```
%APPDATA%\KeyGuardPro\KeyGuardPro.db
```

## ✅ **Project Status**

### 🎯 **Implementation Complete**
- **✅ Build Status**: Compiles successfully with .NET 9
- **✅ UI Implementation**: Modern dark-themed interface with circular scanner
- **✅ Core Features**: All primary functionality implemented and tested
- **✅ Admin Privileges**: Properly configured UAC elevation for system access
- **✅ Release Ready**: Self-contained executable available in Release folder
- **✅ Launch Scripts**: Easy-to-use batch files for streamlined startup

### 🚀 **Ready for Use**
The application is fully functional and ready for deployment:

1. **✅ Builds Successfully**: No compilation errors, clean build output
2. **✅ Requires Admin**: Properly configured UAC elevation manifest
3. **✅ Complete Feature Set**: All requested functionality implemented
4. **✅ Professional UI**: Modern dark theme with circular scanning interface
5. **✅ Comprehensive Documentation**: Updated README with full feature details
6. **✅ Multiple Launch Options**: Batch scripts and direct executable access

## 🔧 Troubleshooting

### Common Issues
1. **UAC Elevation Required**: Always run as Administrator for full functionality
2. **Windows Defender Alerts**: Add exception for KeyGuard Pro if false positive occurs
3. **Process Access Denied**: Some system processes may be protected by Windows
4. **Performance Impact**: Intensive scanning may temporarily increase CPU usage

### Support & Debugging
- Enable debug logging in Settings for detailed troubleshooting
- Check Windows Event Viewer for system-level error information
- Review SQLite database logs for historical analysis
- Ensure all dependencies are properly installed

## 📝 License & Legal

This project is developed for educational and legitimate security research purposes. Users are responsible for ensuring they have proper authorization before scanning or terminating processes on any system.

### Disclaimer
KeyGuard Pro is designed for defensive security purposes. The developers are not responsible for any misuse of this software. Always comply with local laws and regulations regarding system monitoring and process control.

### Privacy Policy
- **No Data Collection**: KeyGuard Pro does not collect, store, or transmit any personal data
- **Local Processing**: All analysis occurs locally on your machine
- **Audit Logs**: Only local activity logs are maintained for security purposes
- **No Telemetry**: No usage statistics or telemetry data is transmitted

## 🤝 Contributing

Contributions are welcome for:
- Improving detection algorithms and reducing false positives
- Adding new threat signatures and behavioral patterns
- Enhancing the user interface and user experience
- Performance optimizations and code quality improvements
- Documentation updates and troubleshooting guides

## 📞 Support

For support, bug reports, or feature requests:
- Create an issue in the project repository
- Provide detailed system information and error logs
- Include steps to reproduce any issues encountered
- Specify your Windows version and .NET installation details

---

**KeyGuard Pro v1.0** - Advanced Keylogger Detection & System Protection  
© 2025 Security Solutions. All rights reserved.
