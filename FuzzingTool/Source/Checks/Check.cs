using System;
using System.Collections.Generic;
using System.Linq;


namespace Checks
{
    public static class CheckUtils
    {
        public static string EnsureValidUrl(string url)
        {
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
            {
                url = $"http://{url}";
            }
            return url;
        }

        public static List<string> CleanFileTypes(string input)
        {
            return input.Split(",")
                .Select(item => item.Trim())
                .Where(item => !string.IsNullOrEmpty(item))
                .Select(item => "." + item)
                .ToList();
        }
        public static void ShowHelp()
        {
            Console.WriteLine("Use of the program:");
            Console.WriteLine("WebDirectoryAnalyzer [options]");
            Console.WriteLine();
            Console.WriteLine("Available options:");
            Console.WriteLine("  -u <url>          Specifies the base URL to scan.");
            Console.WriteLine("  -w <wordlist>  Specifies the dictionary file with the words to test.");
            Console.WriteLine("  -fs <code>      Filter by HTTP status code (example: 200).");
            Console.WriteLine("  -fw <words number>      Filter by minimum number of words on the page.");
            Console.WriteLine("  -ft <types>       Filters by comma-separated file types (example: php,txt).");
            Console.WriteLine("  --analyze         Perform additional analysis searching for differents typical sensitive expressions.");
            Console.WriteLine("  --pattern         Allow input of custom pattern wordlists");
            Console.WriteLine("  -h                Show help.");
            Console.WriteLine();
            Console.WriteLine("Basic example:");
            Console.WriteLine("  program.exe -u webpage.com -w wordlist.txt");
            Console.WriteLine();
            Console.WriteLine("Full example:");
            Console.WriteLine("  program.exe -u webpage.com -w wordlist.txt -fs 200 -fw 18 -ft php,txt,html,pdf --analyze");
        }
    }   
}