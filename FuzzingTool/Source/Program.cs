using System;
using System.Collections.Generic;
using System.IO;
using Checks;
using Functions;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            // ShowHelp is the function to show the manual
            Checks.CheckUtils.ShowHelp();
            return;
        }
        //Show help if -h is in use
        if (args.Length <= 1 && args[0] == "-h")
        {
            //ShowHelp is the function to show manual
            Checks.CheckUtils.ShowHelp();
            return;
        }

        //Create arguments variables
        string url = "";
        string wordlistPath = "";
        string patternFile = "";
        
        //This variables can be null, bcs not always we use filters
        int? filterStatus = null;
        int? filterWords = null;

        bool analyze = false;

        List<string> fileTypes = new List<string>();
        //List<string> fileTypes = list.Split(",").ToList();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-u":
                    if (i + 1 < args.Length) url = Checks.CheckUtils.EnsureValidUrl(args[++i]);
                    else Console.WriteLine("[!] Missing value for -u");
                    break;
                case "-w":
                    if (i + 1 < args.Length) wordlistPath = args[++i];
                    else Console.WriteLine("[!] Missing value for -w");
                    break;
                case "-fs":
                    if (i + 1 < args.Length) filterStatus = int.Parse(args[++i]);
                    else Console.WriteLine("[!] Missing value for -fs");
                    break;
                case "-fw":
                    if (i + 1 < args.Length) filterWords = int.Parse(args[++i]);
                    else Console.WriteLine("[!] Missing value for -fw");
                    break;
                case "--analyze":
                    analyze = true;
                    break;
                case "-ft":
                    if (i + 1 < args.Length) fileTypes = Checks.CheckUtils.CleanFileTypes(args[++i]);
                    else Console.WriteLine("[!] Missing value for -ft");
                    break;
                case "--pattern":
                    if (i + 1 < args.Length) patternFile = args[++i];
                    else Console.WriteLine("[!] Missing value for --pattern");
                    break;
                default:
                    Console.WriteLine($"Unknown argument: {args[i]}");
                    break;
                }
        }

        //Basic validations
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(wordlistPath))
        {
            Checks.CheckUtils.ShowHelp();
            return;
        }

        if (!File.Exists(wordlistPath))
        {
            Console.WriteLine($"{wordlistPath} does not exist.");
        }

        if (!string.IsNullOrEmpty(patternFile) && !File.Exists(patternFile) && analyze)
        {
            Console.WriteLine($"[!] Pattern file not found ({patternFile}), using default patterns.");
        }

        //Pass arguments to the startup function.
        await Functions.PentestingUtils.Startup(url, wordlistPath, filterStatus, filterWords, analyze, fileTypes, patternFile);
    }
}
