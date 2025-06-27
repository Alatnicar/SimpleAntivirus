using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

class PythonScriptExecutor
{
    // List to store names of Python scripts (relative to the executable directory)
    private static readonly List<string> PythonScripts = new List<string>
    {
        // Add your Python script names here (no path, just filenames)
        "GVPN.py",
        "Simple_Antivirus.py"
        // Add more script names as needed
    };

    static void Main(string[] args)
    {
        // Get the directory of the executable (same as Program.cs at runtime)
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        foreach (var scriptName in PythonScripts)
        {
            // Construct the full path to the Python script
            string scriptPath = Path.Combine(baseDirectory, scriptName);
            ExecutePythonScript(scriptPath);
        }
    }

    static void ExecutePythonScript(string scriptPath)
    {
        try
        {
            // Check if the script file exists
            if (!File.Exists(scriptPath))
            {
                Console.WriteLine($"Script not found: {scriptPath}");
                return;
            }

            // Configure the process to run the Python script
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "python", // Assumes 'python' is in system PATH
                Arguments = $"\"{scriptPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (Process process = new Process { StartInfo = startInfo })
            {
                process.Start();

                // Capture output and errors
                string output = process.StandardOutput.ReadToEnd();
                string errors = process.StandardError.ReadToEnd();

                process.WaitForExit();

                // Display results
                Console.WriteLine($"Executing: {scriptPath}");
                if (!string.IsNullOrEmpty(output))
                    Console.WriteLine($"Output: {output}");
                if (!string.IsNullOrEmpty(errors))
                    Console.WriteLine($"Errors: {errors}");
                Console.WriteLine("------------------------");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing {scriptPath}: {ex.Message}");
        }
    }

    // Method to add new script names (for future extensibility)
    public static void AddPythonScript(string scriptName)
    {
        if (!PythonScripts.Contains(scriptName))
        {
            PythonScripts.Add(scriptName);
        }
    }
}