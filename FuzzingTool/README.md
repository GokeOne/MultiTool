# Description

Description
This Bash script is a versatile fuzzing tool that automates different types of fuzzing tasks using ffuf (Fuzz Faster U Fool). It can perform directory fuzzing, GET and POST parameter fuzzing, and subdomain fuzzing against a target URL. Additionally, the script supports filtering options to refine the results.


# Features

- Directory Fuzzing: Tests for common directories or files on a web server.
- GET Fuzzing: Fuzzes parameters in GET requests.
- POST Fuzzing: Fuzzes parameters in POST requests.
- Subdomain Fuzzing: Discovers subdomains related to a target domain.
- Custom Filters: Filters results based on HTTP status codes, response size, or word count.

# Prerequisites

ffuf: Fuzzing tool used to perform the fuzzing operations. You can install it with:

`sudo apt install ffuf`

# Usage

`./script.sh -u <url> -w <wordlist> [-o <option>] [-f <filter>]`

## Options
- -u: URL to fuzz (required).
- -w: Path to the wordlist file (required).
- -o: Type of fuzzing (required):
    1: Directory Fuzzing
    2: GET Fuzzing
    3: POST Fuzzing
    4: Subdomain Fuzzing
- -f: Filtering options (optional):
    1: Only 200 responses (success).
    2: Ignore empty responses.
    3: Ignore responses with exactly 18 words.
- -h: Show the help message.


**Note**: Please use this tool responsibly and only against domains you have permission to test. Unauthorized testing can be illegal or unethical.
