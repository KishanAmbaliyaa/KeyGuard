using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace KeyloggerDetector.Models
{
    /// <summary>
    /// Hierarchical wrapper for ProcessInfo that supports tree structure
    /// Enables parent-child relationships and grouping like Windows 11 Task Manager
    /// </summary>
    public class ProcessNodeViewModel : INotifyPropertyChanged
    {
        private bool _isExpanded = false;
        private string _category = string.Empty;

        public ProcessNodeViewModel(ProcessInfo processDetails)
        {
            ProcessDetails = processDetails;
            Children = new ObservableCollection<ProcessNodeViewModel>();
        }

        /// <summary>
        /// The original process data
        /// </summary>
        public ProcessInfo ProcessDetails { get; set; }

        /// <summary>
        /// Group category: "Apps", "Background processes", "Windows processes"
        /// </summary>
        public string Category 
        { 
            get => _category;
            set
            {
                _category = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Child processes for hierarchical display
        /// </summary>
        public ObservableCollection<ProcessNodeViewModel> Children { get; set; }

        /// <summary>
        /// Whether this node is expanded in the tree view
        /// </summary>
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                _isExpanded = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Indicates if this process has child processes
        /// </summary>
        public bool HasChildren => Children.Count > 0;

        /// <summary>
        /// Display name for the process (name + child count if applicable)
        /// </summary>
        public string DisplayName
        {
            get
            {
                var name = ProcessDetails.Name;
                if (HasChildren)
                    name += $" ({Children.Count})";
                return name;
            }
        }

        /// <summary>
        /// Formatted memory usage for display
        /// </summary>
        public string FormattedMemoryUsage
        {
            get
            {
                var bytes = ProcessDetails.MemoryUsage;
                if (bytes < 1024) return $"{bytes} B";
                if (bytes < 1024 * 1024) return $"{bytes / 1024:F1} KB";
                if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024 * 1024):F1} MB";
                return $"{bytes / (1024 * 1024 * 1024):F1} GB";
            }
        }

        /// <summary>
        /// Indentation level for tree display (0 = root, 1 = child, etc.)
        /// </summary>
        public int IndentLevel { get; set; } = 0;

        /// <summary>
        /// Pixel width for indentation in UI
        /// </summary>
        public int IndentPixels => IndentLevel * 20;

        /// <summary>
        /// Whether this is a child process (indented)
        /// </summary>
        public bool IsChild => IndentLevel > 0;

        /// <summary>
        /// Whether this is a group node (for service groups)
        /// </summary>
        public bool IsGroup => ProcessDetails.Id == -1;

        /// <summary>
        /// Symbol for expand/collapse button
        /// </summary>
        public string ExpanderSymbol => IsExpanded ? "▼" : "▶";

        /// <summary>
        /// Margin for tree indentation in UI
        /// </summary>
        public string IndentMargin => new string(' ', IndentLevel * 4);

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Refresh computed properties when children change
        /// </summary>
        public void RefreshDisplayProperties()
        {
            OnPropertyChanged(nameof(DisplayName));
            OnPropertyChanged(nameof(HasChildren));
            OnPropertyChanged(nameof(FormattedMemoryUsage));
            OnPropertyChanged(nameof(ExpanderSymbol));
            OnPropertyChanged(nameof(IndentPixels));
            OnPropertyChanged(nameof(IsChild));
            OnPropertyChanged(nameof(IsGroup));
        }
    }
}
