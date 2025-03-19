# Description

Description
This program has several functionalities, is a program that uses GET requests to try to find hidden directories in a web service. We can also analyze the content of each page we find, to try to find sensitive patterns.


# Features

- Directory Fuzzing: Tests for common directories or files on a web server.
- GET Fuzzing: Fuzzes parameters in GET requests.
- Custom Filters: Filters results based on HTTP status codes, response size, or word count.

# Usage

Use of the program:

WebDirectoryAnalyzer [options]

Available options:
- -u <url>          Specifies the base URL to scan.
- -w <wordlist>  Specifies the dictionary file with the words to test.
- -fs \<code>      Filter by HTTP status code (example: 200).
- -fw <words number>      Filter by minimum number of words on the page.
- -ft <types>       Filters by comma-separated file types (example: php,txt).
- --analyze         Perform additional analysis searching for differents typical sensitive expressions.
- --pattern         Allow input of custom pattern wordlists.
- -h                Show help.

Basic example:

  > program.exe -u webpage.com -w wordlist.txt

Full example:

  > program.exe -u webpage.com -w wordlist.txt -fs 200 -fw 18 -ft php,txt,html,pdf --analyze
  

**Note**: Please use this tool responsibly and only against domains you have permission to test. Unauthorized testing can be illegal or unethical.
