using System;
using Microsoft.Data.Sqlite;

namespace KeyloggerDetector.Services
{
    public class DatabaseManagerSimple
    {
        private readonly string connectionString;
        
        public DatabaseManagerSimple()
        {
            connectionString = "Data Source=test.db";
        }
        
        public void Test()
        {
            // Simple test method
        }
    }
}
