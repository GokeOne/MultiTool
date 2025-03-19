using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.IO;
using System.Linq;
using Checks;

//Define namespace and principal function of functions PentestingUtils
namespace Functions
{
    public class PentestingUtils
    {   
        //Make http static client,we can reuse it in all request
        private static readonly HttpClient client = new HttpClient();

        //Principal method, starts the process

        public static async Task Startup(string url, string wordlistPath, int? filterStatus, int? filterWords, bool analyze, List<string> fileTypes, string filePattern)
        {
            //Verify if we put the url and wordlist, it should not enter never here
            if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(wordlistPath))
            {
                Console.WriteLine("[!] URL and Wordlist are required.");
                Checks.CheckUtils.ShowHelp();
                return;
            }

            //Check if wordlist file exists
            if (!File.Exists(wordlistPath))
            {
                Console.WriteLine($"[!] Wordlist file not found: {wordlistPath}");
                return;
            }

            //Read all lines of file, using asyncrone method
            var words = await File.ReadAllLinesAsync(wordlistPath);

            // Iterate over all the word of wordlist
            foreach (var word in words)
            {

                //Make sure the word is clean to use
                var sanitizedWord = word.Trim();
                //Leave out the word if its empty
                if (string.IsNullOrEmpty(sanitizedWord)) continue;

                if (fileTypes != null && fileTypes.Any())
                {
                    foreach (var fileType in fileTypes)
                    {
                        // avoid double slash in the URL
                        string fullUrl = $"{url.TrimEnd('/')}/{sanitizedWord}{fileType}";
                        //Make the http request, to the build url
                        await MakeRequest(fullUrl, filterStatus, filterWords, analyze, fileTypes, filePattern);
                    }
                }
                else
                {
                    string fullUrl = $"{url.TrimEnd('/')}/{sanitizedWord}";
                    await MakeRequest(fullUrl, filterStatus, filterWords, analyze, fileTypes ?? new List<string>(), filePattern);
                }
                
            }
        }


        //Private method, make the http request and process the response
        private static async Task MakeRequest(string url, int? filterStatus, int? filterWords, bool analyze, List<string> fileTypes, string filePattern)
        {
            try
            {
                //Make GET request in the url specified
                HttpResponseMessage response = await client.GetAsync(url);
                //Read the content of response lika a chain
                string content = await response.Content.ReadAsStringAsync();

                //Get the code of status response
                int statusCode = (int)response.StatusCode;
                //Count the amount of words in the response content
                int wordCount = content.Split(new char[] { ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries).Length;

                // If code status is 404, ignore the URL
                if (statusCode == 404) return;

                // Check if code status matches with the filter (if we specified)
                bool statusOk = filterStatus == null || statusCode == filterStatus;
                //Check if the amount of word meets with filter (if we specified)
                bool wordsOk = filterWords == null || wordCount >= filterWords;
                //Check if the type of file meets with the permited types (if we specified)
                bool fileTypeOk = fileTypes == null || fileTypes.Count == 0 || fileTypes.Any(type => url.EndsWith(type, StringComparison.OrdinalIgnoreCase));

                // If all the filter are valids, prcoess the url
                if (statusOk && wordsOk && fileTypeOk)
                {
                    // If the analyze is actived, search for sensitive patterns in the content
                    string matchedPattern = "";
                    if (analyze)
                    {
                        var sensitiveData = await AnalyzeContent(content, filePattern); //Analyze the content in search of sensitive data
                        matchedPattern = sensitiveData.Any() ? string.Join(",", sensitiveData.Distinct()) : "None"; //Reset the results 
                    }

                    // Show the output with the correct format
                    Console.WriteLine($"+ Matched url: {url} | Status: {statusCode} | Words: {wordCount} | Pattern: {matchedPattern}");
                }
            }
            catch (HttpRequestException)
            {
                // Ignore 404 , timeouts o errors
            }
            catch (Exception ex)
            {
                //We throw any other type of exception and show an error message
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        //This method analyze the content in search of sensitive patterns
        public static async Task<List<string>> AnalyzeContent(string content, string patternFile)
        {
            //Consistency to found the patterns in content
            content = content.Replace("\r\n", "\n").Replace("\r", "\n");

            //Initialize the list to store the sensitive data founds
            List<string> sensitiveData = new List<string>();

            //Initialize the listo to store the patterns
            List<string> patterns = new List<string>();

            if (!string.IsNullOrEmpty(patternFile) && File.Exists(patternFile))
            {
                var patternsArray = await File.ReadAllLinesAsync(patternFile);
                patterns = patternsArray.ToList();
            }
            else
            {
                patterns.AddRange(new List<string>
                {
                    @"(?i)\b(user|usuario|cliente|password|cred|credential|secret|key|auth|token|hash|cookie|credentials)\b",
                    //Github Dorking
                    "0dysAuQ5KQk=",
                    "0GITHUB_TOKEN=",
                    "0HB_CODESIGN_GPG_PASS=",
                    "0HB_CODESIGN_KEY_PASS=",
                    "0KNAME=",
                    "0NC6O0ThWq69BcWmrtbD2ev0UDivbG8OQ1ZsSDm9UqVA=",
                    "0PUSHOVER_TOKEN=",
                    "0PUSHOVER_USER=",
                    "0PYg1Q6Qa8BFHJDZ0E8F4thnPFDb1fPnUVIgfKmkE8mnLaQoO7JTHuvyhvyDA=",
                    "0VIRUSTOTAL_APIKEY=",
                    "0YhXFyQ=",
                    "1ewh8kzxY=",
                    "1LRQzo6ZDqs9V9RCMaGIy2t4bN3PAgMWdEJDoU1zhuy2V2AgeQGFzG4eanpYZQqAp6poV02DjegvkXC7cA5QrIcGZKdrIXLQk4TBXx2ZVigDio5gYLyrY=",
                    "2bS58p9zjyPk7aULCSAF7EUlqT041QQ5UBJV7gpIxFW1nyD6vL0ZBW1wA1k1PpxTjznPA=",
                    "3FvaCwO0TJjLU1b0q3Fc=",
                    "6EpEOjeRfE=",
                    "6mSMEHIauvkenQGZlBzkLYycWctGml9tRnIpbqJwv0xdrkTslVwDQU5IEJNZiTlJ2tYl8og=",
                    "6tr8Q=",
                    "7h6bUpWbw4gN2AP9qoRb6E6ITrJPjTZEsbSWgjC00y6VrtBHKoRFCU=",
                    "7QHkRyCbP98Yv2FTXrJFcx9isA2viFx2UxzTsvXcAKHbCSAw=",
                    "8FWcu69WE6wYKKyLyHB4LZHg=",
                    "47WombgYst5ZcnnDFmUIYa7SYoxZAeCsCTySdyTso02POFAKYz5U=",
                    ".mlab.com password",
                    "access_key",
                    "access_token",
                    "amazonaws",
                    "api.googlemaps AIza",
                    "api_key",
                    "api_secret",
                    "apidocs",
                    "apikey",
                    "apiSecret",
                    "app_key",
                    "app_secret",
                    "appkey",
                    "appkeysecret",
                    "application_key",
                    "appsecret",
                    "appspot",
                    "auth",
                    "auth_token",
                    "authorizationToken",
                    "aws_access",
                    "aws_access_key_id",
                    "aws_key",
                    "aws_secret",
                    "aws_token",
                    "AWSSecretKey",
                    "bashrc password",
                    "bucket_password",
                    "client_secret",
                    "cloudfront",
                    "codecov_token",
                    "consumer_key",
                    "credentials",
                    "database_password",
                    "db_password",
                    "db_username",
                    "dbpasswd",
                    "dbpassword",
                    "dbuser",
                    "dot-files",
                    "dotfiles",
                    "encryption_key",
                    "fabricApiSecret",
                    "fb_secret",
                    "firebase",
                    "secret_key",
                    "secret_token",
                    "secrets",
                    "secure",
                    "security_credentials",
                    "send.keys",
                    "send_keys",
                    "sendkeys",
                    "SF_USERNAME salesforce",
                    "sf_username",
                    "slack_api",
                    "slack_token",
                    "sql_password",
                    "ssh2_auth_password",
                    "-----BEGIN DSA PRIVATE KEY-----",
                    "-----BEGIN EC PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "--password=",
                    "-DSELION_BROWSER_RUN_HEADLESS=",
                    "-DSELION_DOWNLOAD_DEPENDENCIES=",
                    "-DSELION_SELENIUM_RUN_LOCALLY=",
                    "-DSELION_SELENIUM_USE_GECKODRIVER=",
                    "ACCESS KEY ID =",
                    "ACCESS_KEY=",
                    "ACCESS_KEY_ID=",
                    "ACCESS_KEY_SECRET=",
                    "ACCESS_SECRET=",
                    "ACCESS_TOKEN=",
                    "accessibilityChecks=",
                    "ACCESSKEY=",
                    "ACCESSKEYID=",
                    "ACCOUNT_SID=",
                    //Regex4mail address \\ to escape
                    //"^[\\w\\.=-]+@[\\w\\.-]+\\.[\\w]{2,3}$",

                    //URL Robust (So many information, dont use. )
                    //@"https?://[^\s/$.?#].[^\s]*", 

                    //U.S Social security numbers
                    @"\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))([-]?|\s{1})(?!00)\d\d\2(?!0000)\d{4}\b",
                    //IPV4 Addresses
                    @"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$",
                    //Dates in MM/DD/YYYY format
                    @"^([1][12]|[0]?[1-9])[\/-]([3][01]|[12]\d|[0]?[1-9])[\/-](\d{4}|\d{2})$",
                    //MasterCard numbers
                    @"^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$",
                    //Visa card numbers
                    @"\b([4]\d{3}[\s]\d{4}[\s]\d{4}[\s]\d{4}|[4]\d{3}[-]\d{4}[-]\d{4}[-]\d{4}|[4]\d{3}[.]\d{4}[.]\d{4}[.]\d{4}|[4]\d{3}\d{4}\d{4}\d{4})\b",
                    //American Express card numbers
                    @"^3[47][0-9]{13}$",
                    //U.S ZIP Codes
                    @"^((\d{5}-\d{4})|(\d{5})|([A-Z]\\d[A-Z]\s\d[A-Z]\d))$",


                    //File paths
                    //@"\\[^\\]+$",
                    //Unix File paths
                    //@"[/\\][^/\\]+$",

                    //URLs
                    //"(?i)\b((?:[a-z][\\w-]+:(?:\\/{1,3}|[a-z0-9%])|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}\\/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))",

                    //Amex Card
                    @"^3[47][0-9]{13}$",
                    //BCGlobal
                    @"^(6541|6556)[0-9]{12}$",
                    //Carte Blanche Card
                    @"^389[0-9]{11}$",
                    //Diners Club Card
                    @"^3(?:0[0-5]|[68][0-9])[0-9]{11}$",
                    //Discover Card
                    @"^65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})$",
                    //Insta Payment Card
                    @"^63[7-9][0-9]{13}$",
                    //JCB Card
                    @"^(?:2131|1800|35\d{3})\d{11}$",
                    //KoreanLocalCard
                    @"^9[0-9]{15}$",
                    //Laser Card
                    @"^(6304|6706|6709|6771)[0-9]{12,15}$",
                    //Maestro Card
                    @"^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$",
                    //Mastercard
                    @"^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$",
                    //Solo Card
                    @"^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$",
                    //Switch Card
                    @"^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$",
                    //Union Pay Card
                    @"^(62[0-9]{14,17})$",
                    //Visa Card
                    @"^4[0-9]{12}(?:[0-9]{3})?$",
                    //Visa Master Card
                    @"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$",
                    //-------------------------------------------------
                    @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",   // Emails -- ByChatGPT
                    @"\b\d{4}-\d{4}-\d{4}-\d{4}\b",                    // Credit Cards -- ByChatGPT
                    @"\b(?:\d{4}[- ]?){3}\d{4}\b"                       //Credit cars without dash -- ByQwen2.5
                });
            }
            

            //Iterate over any pattern , and search coincidence
            foreach (var pattern in patterns)
            {
                var matches = Regex.Matches(content, pattern); //Search coincidence in the actual pattern
                foreach (Match match in matches)
                {
                    sensitiveData.Add(match.Value); //Add any coincidence to the list of sensitive data
                }
            }
            //Return the list
            return sensitiveData;
        }
    }
}
