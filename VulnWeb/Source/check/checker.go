package check

import (
	"fmt"
	"regexp"
)

func Usage() {
	fmt.Println("Usage ./vulnweb -u <url>")
}

func ValidateURL(url string) error {
	regex := `^((https?|ftp):\/\/)?([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/.*)?$`
	re := regexp.MustCompile(regex)

	if !re.MatchString(url) {
		return fmt.Errorf("Invalid URL format: %s", url)
	}
	return nil
}
