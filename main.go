package main

import (
	"flag"
	"fmt"
	"net/url"
	query "nvdsearch/query"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
)

var cveBaseURL string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
var productBaseURL string = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

func main() {
	figure.NewColorFigure("nvdsearch", "doom", "yellow", true).Print()
	color.Yellow("\t\t\t\t\t\t@h0useh3ad\n\n")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-interrupt
		fmt.Println("\nExiting...")
		os.Exit(0)
	}()

	cpelookup := flag.String("cpelookup", "", "CPE name lookup for product (Ex: openssl or 'apache 2.4')")
	vendor := flag.String("vendor", "", "Vendor name")
	product := flag.String("product", "", "Product name")
	version := flag.String("version", "", "Product version")
	cveid := flag.String("cveid", "", "CVE ID (Ex: CVE-2023-34362 or 2023-34362)")
	cpe := flag.String("cpe", "", "CPE version 2.3 format (Ex: cpe:2.3:a:progress:moveit_transfer:2023.0.1:*:*:*:*:*:*:*)")
	output := flag.String("output", "", "Output filename")
	flag.Parse()

	if *cveid != "" {
		cveID := strings.ToUpper(*cveid)
		if !strings.HasPrefix(cveID, "CVE-") {
			cveID = "CVE-" + cveID
		}
		cveID = url.PathEscape(cveID)
		cveID = strings.Replace(cveID, "%E2%80%91", "%2D", -1)
		apiURL := fmt.Sprintf("%s?cveId=%s", cveBaseURL, cveID)
		color.Cyan("\nRequesting: %s\n\n", apiURL)
		query.CveQuery(apiURL, cveID, *output)
	} else if *vendor != "" && *product != "" && *version != "" {
		cpeFormat := fmt.Sprintf("cpe:2.3:a:%s:%s:%s", *vendor, *product, *version)
		cpeURI := url.PathEscape(cpeFormat)
		apiURL := fmt.Sprintf("%s?cpeName=%s", cveBaseURL, cpeURI)
		color.Cyan("\nRequesting: %s\n\n", apiURL)
		query.ProdQuery(apiURL, *vendor, *product, *version, *output)
	} else if *cpelookup != "" {
		if strings.Contains(*cpelookup, " ") {
			cpe := strings.ReplaceAll(*cpelookup, " ", "+")
			apiURL := fmt.Sprintf("%s?keywordSearch=%s", productBaseURL, cpe)
			color.Cyan("\nRequesting: %q\n\n", apiURL)
			query.SearchQuery(apiURL, cpe, *output)
		} else {
			apiURL := fmt.Sprintf("%s?keywordSearch=%s", productBaseURL, *cpelookup)
			color.Cyan("\nRequesting: %q\n\n", apiURL)
			query.SearchQuery(apiURL, *cpelookup, *output)
		}
	} else if *cpe != "" {
		apiURL := fmt.Sprintf("%s?cpeName=%s", cveBaseURL, *cpe)
		color.Cyan("\nRequesting: %q\n\n", apiURL)
		query.CpeQuery(apiURL, *cpe, *output)
	} else {
		color.Red("Please provide either the vendor, product, version flags, cveid flag, cpelookup flag, or cpe flag.")
	}
}
