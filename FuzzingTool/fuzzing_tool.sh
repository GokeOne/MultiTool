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



usage() {
    echo -e "${GREEN}Usage: $0 -u <url> -w <wordlist> [-o <option>] [-f <filter>]${NC}"
    echo -e "${BLUE}Options:${NC}"
    echo "  -u   URL to fuzz"
    echo "  -w   Path to wordlist"
    echo "  -o   Type of fuzzing:"
    echo "         1) Directory Fuzzing"
    echo "         2) GET Fuzzing"
    echo "         3) POST Fuzzing"
    echo "         4) Subdomain Fuzzing"
    echo "  -f   Filter options (optional):"
    echo "         1) Only 200 responses"
    echo "         2) Ignore empty responses"
    echo "         3) Ignore 18 words"
    echo "         *) No filters"
    echo "  -h   Show this help message"
    exit 1
}

add_filter() {
    case $filter in
        1) filter_flag="-mc 200" ;;
        2) filter_flag="-fs 0" ;;
        3) filter_flag="-fw 18" ;;
        *) filter_flag="" ;;
    esac
}

while getopts "u:w:o:f:h" opt; do
    case ${opt} in
        u) url="$OPTARG" ;;
        w) wordlist="$OPTARG" ;;
        o) option="$OPTARG" ;;
        f) filter="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validación de parámetros obligatorios
if [[ -z "$url" || -z "$wordlist" || -z "$option" ]]; then
    usage
fi

# Validar si el archivo wordlist existe
if ! [[ -f "$wordlist" ]]; then
    echo -e "[${RED}ERROR${NC}]The wordlist file is unreachable."
    exit 2
fi

# Validar URL
regex='^((https?|ftp):\/\/)?([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/.*)?$'
if [[ "$url" =~ $regex ]]; then
    all="${BASH_REMATCH[0]}"
    prefix="${BASH_REMATCH[1]}"
    domain="${BASH_REMATCH[3]}"
    port="${BASH_REMATCH[4]}"
    rest="${BASH_REMATCH[5]}"
else
    echo -e "[${RED}ERROR${NC}]This URL is not valid.${NC}"
    exit 1
fi

# Aplicar filtro si se especifica
add_filter

# Proceso de acuerdo a la opción de fuzzing seleccionada
case $option in
    1)  # Directory Fuzzing
        echo -e "${BLUE}Directory Fuzzing${NC}"
        if [[ -z "$port" ]]; then
            command="ffuf -u ${url%/}/FUZZ -w ${wordlist} $filter_flag"
        else
            command="ffuf -u ${url%/}:${port}/FUZZ -w ${wordlist} $filter_flag"
        fi
        ;;
    2)  # GET Fuzzing
        echo -e "${BLUE}GET Fuzzing${NC}"
        command="ffuf -u ${all}FUZZ -w ${wordlist} $filter_flag"
        ;;
    3)  # POST Fuzzing
        echo -e "${BLUE}POST Fuzzing${NC}"
        read -p "Set POST data (example: username=admin&password=FUZZ): " post_data
        command="ffuf -u ${prefix}${domain}:${port:-80}${rest} -X POST -d \"${post_data}\" -w ${wordlist} $filter_flag"
        ;;
    4)  # Subdomain Fuzzing
        echo -e "${BLUE}Subdomain Fuzzing${NC}"
        command="ffuf -u ${prefix}FUZZ.${domain}:${port:-80}/ -w ${wordlist} -H \"Host: FUZZ.${domain}\" $filter_flag"
        ;;
    *)
        echo -e "${RED}Invalid option or exiting...${NC}"
        exit 3
        ;;
esac

# Ejecutar el comando
eval "$command"
