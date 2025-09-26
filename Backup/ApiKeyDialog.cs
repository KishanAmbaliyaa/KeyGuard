using System;
using System.Windows;

namespace KeyloggerDetector
{
    public class ApiKeyDialog : Window
    {
        public string ApiKey { get; private set; } = string.Empty;

        public ApiKeyDialog()
        {
            // Simple dialog without XAML
            Title = "API Key Configuration";
            Width = 400;
            Height = 200;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            // For now, just close without requiring an API key
            this.DialogResult = true;
            this.Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }
    }
}
