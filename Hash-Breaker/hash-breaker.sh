#!/bin/bash

# Color Definitions
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
NC="${C}[0m" # No Color

# Report time mark
date=$(date +'%d_%m_%Y_%H%M%S')
report="report_$date.txt"

wordlist=""
hash_type=""
threads=1
hash_input=""
sleep_time=0
output_file=""

usage() {
    echo -e "${GREEN}Usage: $0 -m <hash_type> -w <wordlist> -t <threads>${NC}"
    echo -e "${GREEN}Options:${NC}"
    echo -e "       -m Hash type: md5 = 1, sha-1 = 2, sha-256 = 3, sha-512 = 4"
    echo -e "       -w Wordlist"
    echo -e "       -t Number of threads"
    echo -e "       -s Sleep time (in seconds)"
    echo -e "       -o Output file"
    exit 1
}

calculate_hash() {
    local word=$1
    local hash_type=$2
    case $hash_type in
        1) echo -n "$word" | md5sum | awk '{print $1}' ;;
        2) echo -n "$word" | sha1sum | awk '{print $1}' ;;
        3) echo -n "$word" | sha256sum | awk '{print $1}' ;;
        4) echo -n "$word" | sha512sum | awk '{print $1}' ;;
        *) echo "[${RED}ERROR${NC}] Invalid hash type!" ;;
    esac
}

brute_force_attack() {
    local hash_input=$1
    local wordlist=$2
    local threads=$3
    local sleep_time=$4
    local hash_type=$5

    # Dividir el wordlist en partes según el número de threads
    split --numeric-suffixes=1 -n l/$threads "$wordlist" tmp_wordlist_

    found_file="hash_found.tmp"  # Archivo temporal de control

    rm -f "$found_file"  # Asegurarse de que no exista de una corrida previa

    for ((i = 1; i <= threads; i++)); do
        # Ajustar sufijos de archivos temporales de forma correcta
        suffix=$(printf "%02d" $i)

        {
            while IFS= read -r word; do
                hash=$(calculate_hash "$word" "$hash_type")

                if [[ "$hash" == "$hash_input" ]]; then
                    result="[Brute-Force] Hash found: $word"
                    echo -e "${GREEN}$result${NC}"
                    [[ -n "$output_file" ]] && echo "$result" >> "$output_file"
                    echo "1" > "$found_file"  # Crear archivo para indicar que se encontró el hash
                    break  # Salir del bucle si encontramos el hash
                fi
                sleep "$sleep_time"
            done < "tmp_wordlist_$suffix"

            # Verificar si otro thread ya ha encontrado el hash
            if [[ -f "$found_file" ]]; then
                pkill -P $$  # Matar todos los procesos hijos
                exit 0
            fi
        } &
    done

    wait

    # Verificar si el archivo de control existe
    if [[ ! -f "$found_file" ]]; then
        echo "[${RED}ERROR${NC}] No match found for the given hash."
        exit 1
    else
        rm -f "$found_file"  # Limpiar el archivo de control
    fi
}


while getopts ":m:w:t:s:o:h" opt; do
    case $opt in
        m)
            case $OPTARG in
                1) hash_type=1 ;; # md5
                2) hash_type=2 ;; # sha-1
                3) hash_type=3 ;; # sha-256
                4) hash_type=4 ;; # sha-512
                *) echo "[${RED}ERROR${NC}] Invalid hash type: $OPTARG"; usage ;;
            esac
            ;;
        w)
            wordlist="$OPTARG"
            if [[ ! -f "$wordlist" ]]; then
                echo "[${RED}ERROR${NC}] The specified wordlist does not exist: $wordlist"
                exit 1
            fi
            ;;
        t)
            if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                if [[ "$OPTARG" -le 0 ]]; then
                    echo "[${RED}ERROR${NC}] The number of threads must be at least 1"
                    exit 1
                fi
                threads=$OPTARG
            else
                echo "[${RED}ERROR${NC}] The number of threads must be an integer"
                exit 1
            fi
            ;;
        s)
            if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                sleep_time=$OPTARG
            else
                echo "[${RED}ERROR${NC}] The wait time must be an integer"
                exit 1
            fi
            ;;
        o)
            output_file="$OPTARG"
            if ! touch "$output_file" 2>/dev/null; then
                echo "[${RED}ERROR${NC}] Cannot write to output file: $output_file"
                exit 1
            fi
            ;;
        h) usage ;;
        \?) echo "[${RED}ERROR${NC}] Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "[${RED}ERROR${NC}] The option -$OPTARG requires an argument" >&2; usage ;;
    esac
done

if [[ -z "$hash_type" || -z "$wordlist" ]]; then
    usage
fi

read -p "Enter the hash you want to decrypt: " hash_input
if [[ -z "$hash_input" ]]; then
    echo "[${RED}ERROR${NC}] You must enter a hash for the brute-force attack."
    exit 1
fi

[[ -n "$output_file" ]] && > "$output_file"

echo -e "${GREEN}Initiating brute-force attack with hash type $hash_type...${NC}"
brute_force_attack "$hash_input" "$wordlist" "$threads" "$sleep_time" "$hash_type"

echo -e "${GREEN}Attack completed${NC}"
[[ -n "$output_file" ]] && echo -e "${GREEN}Results saved in $output_file${NC}"

# Limpiar archivos temporales
if ls tmp_wordlist_* 1> /dev/null 2>&1; then
    rm tmp_wordlist_*
fi
