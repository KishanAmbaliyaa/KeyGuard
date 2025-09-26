using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace KeyloggerDetector.Converters
{
    /// <summary>
    /// Converts boolean keyboard hook status to background color
    /// </summary>
    public class StatusBackgroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool hasHooks && hasHooks)
            {
                return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF4444")); // Red for hooks
            }
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#28A745")); // Green for no hooks
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts boolean keyboard hook status to text
    /// </summary>
    public class StatusTextConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool hasHooks && hasHooks)
            {
                return "HOOKS";
            }
            return "CLEAN";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts threat level string to background color
    /// </summary>
    public class ThreatLevelBackgroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string threatLevel)
            {
                return threatLevel.ToLowerInvariant() switch
                {
                    "low" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#28A745")), // Green
                    "medium" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFC107")), // Yellow
                    "high" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC3545")), // Red
                    "critical" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6F1E51")), // Dark Red
                    _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6C757D")) // Gray for unknown
                };
            }
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6C757D"));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts bytes to MB for memory display
    /// </summary>
    public class BytesToMBConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                double mb = bytes / (1024.0 * 1024.0);
                return $"{mb:F1} MB";
            }
            if (value is int intBytes)
            {
                double mb = intBytes / (1024.0 * 1024.0);
                return $"{mb:F1} MB";
            }
            return "0.0 MB";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts boolean to icon text for display
    /// </summary>
    public class BoolToIconConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                return boolValue ? "✓" : "✗";
            }
            return "✗";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
