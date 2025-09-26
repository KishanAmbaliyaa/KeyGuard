using System;

namespace KeyloggerDetector.Models
{
    public class ThreatInfo
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string Description { get; set; }
        public DateTime DetectedAt { get; set; }
        public string ThreatLevelColor => ThreatLevel switch
        {
            ThreatLevel.Critical => "#FF0000",
            ThreatLevel.High => "#FF4444",
            ThreatLevel.Medium => "#FF8800",
            ThreatLevel.Low => "#FFFF00",
            _ => "#00FF00"
        };
    }

    public enum ThreatLevel
    {
        Safe = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}
