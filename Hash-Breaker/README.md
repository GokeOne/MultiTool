# Brute Force Hash Cracker

This Bash script allows you to perform a brute-force attack to decrypt hashes using different hashing algorithms and a wordlist.

## Requirements

Linux or a Bash-compatible system.
Hashing tools like `md5sum`, `sha1sum`, `sha256sum`, and `sha512sum`.

## Usage


`./brute_force_hash_cracker.sh -m <hash_type> -w <wordlist> -t <threads> [-s <sleep_time>] [-o <output_file>]`

## Options

    -m <hash_type>: Specify the hash type:
        1 for MD5
        2 for SHA-1
        3 for SHA-256
        4 for SHA-512

    -w <wordlist>: Path to a file containing the list of words to attempt to crack the hash.

    -t <threads>: Number of threads to use for the attack (must be a positive integer).

    -s <sleep_time>: Sleep time in seconds between hash attempts (optional, default is 0).

    -o <output_file>: File where found results will be saved (optional).

    -h: Displays help and the list of options.

## Example


`./brute_force_hash_cracker.sh -m 1 -w wordlist.txt -t 4 -s 1 -o results.txt`

## Functionality

    The script receives options and validates parameters.
    It prompts the user to enter the hash they want to decrypt.
    It splits the wordlist into parts based on the specified number of threads.
    Each thread attempts to compute the hash for each word in its part and checks if it matches the input hash.
    If a match is found, the result is displayed in the console and saved to the output file, if specified.
    If no match is found, the user is notified.

## Notes

Ensure that the wordlist file exists before running the script.
Using multiple threads can significantly increase the speed of the attack but may also increase the load on the system.
Temporary files generated during execution are automatically cleaned up at the end.

## Contributions

Contributions are welcome! If you wish to enhance the script or add new features, feel free to submit a pull request.
