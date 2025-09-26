using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace KeyloggerDetector.Converters
{
    /// <summary>
    /// Converts string values to Visibility (for showing/hiding UI elements based on text content)
    /// </summary>
    public class StringToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string str && !string.IsNullOrEmpty(str))
            {
                return Visibility.Visible;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts threat level strings to colors for visual indication
    /// </summary>
    public class ThreatLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string threatLevel)
            {
                return threatLevel switch
                {
                    "High" => Colors.Red,
                    "Medium" => Colors.Orange,
                    "Low" => Colors.Yellow,
                    "Safe" => Colors.LimeGreen,
                    _ => Colors.Gray
                };
            }
            return Colors.Gray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts process category to appropriate icon
    /// </summary>
    public class ProcessCategoryToIconConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string category)
            {
                return category switch
                {
                    "Apps" => "📱",
                    "Background processes" => "⚙️",
                    "Windows processes" => "🪟",
                    _ => "⚡"
                };
            }
            return "⚡";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Converts boolean to FontWeight (True = SemiBold, False = Normal)
    /// </summary>
    public class BoolToFontWeightConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool isGroup && isGroup)
            {
                return FontWeights.SemiBold;
            }
            return FontWeights.Normal;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
