using System;

namespace KeyloggerDetector.Models
{
    public class ThreatLog
    {
        public DateTime Timestamp { get; set; }
        public string ProcessName { get; set; }
        public string Action { get; set; }
        public string ThreatLevel { get; set; }
        public string Details { get; set; }
        public string ProcessPath { get; set; }
        public int ProcessId { get; set; }
        
        public string FormattedTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    }
}
