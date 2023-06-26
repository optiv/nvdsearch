package query

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	writecsv "nvdsearch/csv"
	nvdstructs "nvdsearch/structs"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type ProductsResponse struct {
	SearchResponse nvdstructs.SearchResponse
	Products       []nvdstructs.Products
}

func SearchQuery(a string, s string, o string) {
	whitep := color.New(color.FgWhite)
	boldWhite := whitep.Add(color.Bold)
	red := color.New(color.FgRed).PrintfFunc()

	products, err := getProducts(a)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(products.Products) <= 0 {
		if strings.Contains(s, "+") {
			cpel := strings.ReplaceAll(s, "+", " ")
			fmt.Println("\n-----------------------------------")
			red("\nNo CPEs found for search of: ")
			fmt.Printf("%s\n", cpel)
			fmt.Println("\n-----------------------------------")
			return

		} else {
			fmt.Println("\n-----------------------------------")
			red("\nNo CPEs found for search of: ")
			fmt.Printf("%s\n", s)
			fmt.Println("\n-----------------------------------")
			return
		}
	}

	boldWhite.Printf("Total Results: ")
	fmt.Printf("%d\n", products.SearchResponse.TotalResults)
	fmt.Println("\n-----------------------------------")

	if o != "" {
		filename := o + ".csv"
		err = writecsv.WriteProdCSV(filename, products.Products)

		if err != nil {
			color.Red("\nError writing to CSV:", err)
		} else {
			fmt.Printf("\nCSV file created: ")
			color.HiGreen("%v.csv\n\n", o)
			fmt.Printf("-----------------------------------\n\n")
		}

		if products.SearchResponse.TotalResults > 10000 {
			startIndex := 10000
			apiURL := fmt.Sprintf("%s&startIndex=%d", a, startIndex)

			remainingProducts, err := getProducts(apiURL)
			if err != nil {
				fmt.Println(err)
				return
			}
			err = writecsv.WriteAddProdCSV(filename, remainingProducts.Products)
			if err != nil {
				color.Red("\nError writing to CSV:", err)
			}
		}
	}

	if products.SearchResponse.TotalResults >= 250 {
		fmt.Printf("\nTotal results are greater than 250.\n")
		fmt.Println("Would you like to continue and print the results? (y[es] or n[o])")

		var userInput string
		fmt.Scanln(&userInput)
		if userInput != "yes" && userInput != "y" {
			if o != "" {
				fmt.Printf("\n")
				fmt.Println("Exiting...")
				os.Exit(0)
			} else {
				fmt.Printf("\n")
				fmt.Printf("%v %v %v\n", color.WhiteString("The"), color.GreenString("-output"), color.WhiteString("option can be used to write results to CSV."))
				fmt.Println("\nExiting...")
				os.Exit(0)
			}
		}
	}

	for _, products := range products.Products {
		boldWhite.Printf("\nTitle: ")
		fmt.Printf("%v\n", products.CPE.Titles[0].Title)
		boldWhite.Printf("\nCPE Name: ")
		fmt.Printf("%v\n", products.CPE.CpeName)
		boldWhite.Printf("CPE ID: ")
		fmt.Printf("%v\n", products.CPE.CpeNameID)

		createdTime, _ := time.Parse("2006-01-02T15:04:05.000", products.CPE.Created)
		createdDate := createdTime.Format("2006-01-02")
		boldWhite.Printf("\nCreation Date: ")
		fmt.Printf("%v\n", createdDate)

		lastModifiedTime, _ := time.Parse("2006-01-02T15:04:05.000", products.CPE.LastModified)
		lastModifiedDate := lastModifiedTime.Format("2006-01-02")
		boldWhite.Printf("Last Modified Date: ")
		fmt.Printf("%v\n", lastModifiedDate)

		fmt.Println("\n-----------------------------------")
	}

	if products.SearchResponse.TotalResults > 10000 {
		startIndex := 10000
		apiURL := fmt.Sprintf("%s&startIndex=%d", a, startIndex)

		remainingProducts, err := getProducts(apiURL)
		if err != nil {
			fmt.Println(err)
			return
		}

		for _, products := range remainingProducts.Products {
			boldWhite.Printf("\nTitle: ")
			fmt.Printf("%v\n", products.CPE.Titles[0].Title)
			boldWhite.Printf("\nCPE Name: ")
			fmt.Printf("%v\n", products.CPE.CpeName)
			boldWhite.Printf("CPE ID: ")
			fmt.Printf("%v\n", products.CPE.CpeNameID)

			createdTime, _ := time.Parse("2006-01-02T15:04:05.000", products.CPE.Created)
			createdDate := createdTime.Format("2006-01-02")
			boldWhite.Printf("\nCreation Date: ")
			fmt.Printf("%v\n", createdDate)

			lastModifiedTime, _ := time.Parse("2006-01-02T15:04:05.000", products.CPE.LastModified)
			lastModifiedDate := lastModifiedTime.Format("2006-01-02")
			boldWhite.Printf("Last Modified Date: ")
			fmt.Printf("%v\n", lastModifiedDate)

			fmt.Println("\n-----------------------------------")
		}
	}
}

func getProducts(apiURL string) (ProductsResponse, error) {
	var response ProductsResponse

	resp, err := http.Get(apiURL)
	if err != nil {
		return response, fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return response, fmt.Errorf("error reading response body: %v", err)
	}

	err = json.Unmarshal(body, &response.SearchResponse)
	if err != nil {
		return response, fmt.Errorf("error parsing JSON response: %v", err)
	}

	response.Products = response.SearchResponse.Products
	return response, nil
}

func ProdQuery(a string, ven string, pro string, ver string, o string) {
	whitep := color.New(color.FgWhite)
	boldWhite := whitep.Add(color.Bold)
	red := color.New(color.FgRed).PrintfFunc()
	iwhite := color.New(color.FgWhite).SprintFunc()

	resp, err := http.Get(a)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var nvdResponse nvdstructs.NVDResponse
	err = json.Unmarshal(body, &nvdResponse)
	if err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	if nvdResponse.TotalResults > 0 {
		boldWhite.Printf("Total Results: %d\n", nvdResponse.TotalResults)
		fmt.Println("\n-----------------------------------")

		Vulns(nvdResponse.Vulnerabilities)

		if o != "" {
			filename := o + ".csv"
			err = writecsv.WriteCSV(filename, nvdResponse.Vulnerabilities)
			if err != nil {
				red("\nError writing to CSV:", err)
			} else {
				fmt.Printf("\nCSV file created: ")
				color.HiGreen("%v.csv\n\n", o)
				fmt.Println("-----------------------------------")
			}
		}
	} else {
		fmt.Println("\n-----------------------------------")
		fmt.Printf("\n%v %v %v %v %v %v %v\n", color.RedString("No vulnerabilities found for"), color.BlueString("Vendor:"), iwhite(ven), color.BlueString("Product:"), iwhite(pro), color.BlueString("Version:"), iwhite(ver))
		fmt.Println("\n-----------------------------------")
	}
}

func CpeQuery(a string, c string, o string) {
	red := color.New(color.FgRed).PrintfFunc()
	iwhite := color.New(color.FgWhite).SprintFunc()

	resp, err := http.Get(a)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var nvdResponse nvdstructs.NVDResponse
	err = json.Unmarshal(body, &nvdResponse)
	if err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	if nvdResponse.TotalResults > 0 {
		fmt.Printf("Total Results: %d\n", nvdResponse.TotalResults)
		fmt.Println("\n-----------------------------------")

		Vulns(nvdResponse.Vulnerabilities)

		if o != "" {
			filename := o + ".csv"
			err = writecsv.WriteCSV(filename, nvdResponse.Vulnerabilities)
			if err != nil {
				red("\nError writing to CSV:", err)
			} else {
				fmt.Printf("\nCSV file created: ")
				color.HiGreen("%v.csv\n\n", o)
				fmt.Println("-----------------------------------")
			}
		}
	} else {
		fmt.Println("\n-----------------------------------")
		fmt.Printf("\n%v %v %v\n", color.RedString("No vulnerabilities found for"), color.BlueString("CPE:"), iwhite(c))
		fmt.Println("\n-----------------------------------")
	}
}

func CveQuery(a string, c string, o string) {
	whitep := color.New(color.FgWhite)
	boldWhite := whitep.Add(color.Bold)
	cwhite := color.New(color.FgHiWhite).PrintfFunc()
	cblue := color.New(color.FgBlue).PrintfFunc()
	red := color.New(color.FgRed).PrintfFunc()

	resp, err := http.Get(a)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Println("\n-----------------------------------")
		red("\nNo vulnerabilities found for: ")
		fmt.Printf("%v\n", c)
		fmt.Println("\n-----------------------------------")
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var nvdResponse nvdstructs.NVDResponse
	err = json.Unmarshal(body, &nvdResponse)
	if err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	if nvdResponse.TotalResults > 0 {
		for _, vulnerability := range nvdResponse.Vulnerabilities {
			fmt.Println("-----------------------------------")
			boldWhite.Printf("CVE ID: ")
			fmt.Printf("%v\n", vulnerability.CVE.CVEID)

			publishedTime, err := time.Parse("2006-01-02T15:04:05.000", vulnerability.CVE.Published)
			if err == nil {
				publishedDate := publishedTime.Format("2006-01-02")
				boldWhite.Printf("\nPublished Date: ")
				fmt.Printf("%v\n", publishedDate)
			}

			lastModifiedTime, err := time.Parse("2006-01-02T15:04:05.000", vulnerability.CVE.LastModified)
			if err == nil {
				lastModifiedDate := lastModifiedTime.Format("2006-01-02")
				boldWhite.Printf("Last Modified Date: ")
				fmt.Printf("%v\n", lastModifiedDate)
			}

			if len(vulnerability.CVE.Metrics.CvssMetricV2) > 0 {
				for _, cvssv2 := range vulnerability.CVE.Metrics.CvssMetricV2 {
					boldWhite.Printf("\nCVSSv2 Type: ")
					fmt.Printf("%v\n", cvssv2.Type)
					boldWhite.Printf("CVSSv2 Source: ")
					fmt.Printf("%v\n", cvssv2.Source)
					boldWhite.Printf("\tSeverity: ")
					fmt.Printf("%v\n", cvssv2.BaseSev)
					boldWhite.Printf("\tBase Score :")
					fmt.Printf("%v\n", cvssv2.CvssData.BaseScore)
					boldWhite.Printf("\tVector: ")
					fmt.Printf("%v\n", cvssv2.CvssData.Vector)
					boldWhite.Printf("\tImpact Score: ")
					fmt.Printf("%v\n", cvssv2.ImpactScore)
					boldWhite.Printf("\tExploitability Score: ")
					fmt.Printf("%v\n", cvssv2.ExplScore)
				}
			}

			if len(vulnerability.CVE.Metrics.CvssMetricV31) > 0 {
				for _, cvssv3 := range vulnerability.CVE.Metrics.CvssMetricV31 {
					boldWhite.Printf("\nCVSSv3 Type: ")
					fmt.Printf("%v\n", cvssv3.Type)
					boldWhite.Printf("CVSSv3 Source: ")
					fmt.Printf("%v\n", cvssv3.Source)
					boldWhite.Printf("\tSeverity: ")
					fmt.Printf("%v\n", cvssv3.CvssData.BaseSeverity)
					boldWhite.Printf("\tBase Score: ")
					fmt.Printf("%v\n", cvssv3.CvssData.BaseScore)
					boldWhite.Printf("\tVector: ")
					fmt.Printf("%v\n", cvssv3.CvssData.Vector)
					boldWhite.Printf("\tImpact Score: ")
					fmt.Printf("%v\n", cvssv3.ImpScore)
					boldWhite.Printf("\tExploitability Score: ")
					fmt.Printf("%v\n", cvssv3.ExplScore)
				}
			}

			if len(vulnerability.CVE.Weaknesses) > 0 {
				boldWhite.Println("\nWeaknesses:")
				uniqueWeaknesses := []string{}
				for _, weakness := range vulnerability.CVE.Weaknesses {
					weaknessType := weakness.Description[0].Val
					isUnique := true
					for _, uniqueType := range uniqueWeaknesses {
						if weaknessType == uniqueType {
							isUnique = false
							break
						}
					}
					if isUnique {
						boldWhite.Printf("\tType: ")
						fmt.Printf("%v\n", weaknessType)
						uniqueWeaknesses = append(uniqueWeaknesses, weaknessType)
					}
				}
			}

			for _, description := range vulnerability.CVE.Descriptions {
				if description.Language == "en" {
					boldWhite.Printf("\nDescription:\n")
					fmt.Printf("%v\n", description.Value)
					break
				}
			}

			if len(vulnerability.CVE.Configurations) > 0 {
				if len(vulnerability.CVE.Configurations) <= 1 {
					if vulnerability.CVE.Configurations[0].Operator == "" {
						if len(vulnerability.CVE.Configurations[0].Nodes) == 1 && vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
							boldWhite.Println("\nAffected Configurations:")
							cblue("\n\tConfiguration 1:\n")
							for _, configurations := range vulnerability.CVE.Configurations {
								for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
									fmt.Printf("\t  %v\n", cpeMatch.Criteria)
									if len(cpeMatch.VersStartIncl) > 0 {
										cwhite("\t\tFrom (including): ")
										fmt.Printf("%v\n", cpeMatch.VersStartIncl)
									} else if len(cpeMatch.VersStartExcl) > 0 {
										cwhite("\t\tFrom (excluding): ")
										fmt.Printf("%v\n", cpeMatch.VersStartExcl)
									}
									if len(cpeMatch.VersEndInclud) > 0 {
										cwhite("\t\tUp to (including): ")
										fmt.Printf("%v\n", cpeMatch.VersEndInclud)
									} else if len(cpeMatch.VersEndExlud) > 0 {
										cwhite("\t\tUp to (excluding): ")
										fmt.Printf("%v\n", cpeMatch.VersEndExlud)
									}
								}
							}
						}
					} else if vulnerability.CVE.Configurations[0].Operator == "AND" {
						if vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
							boldWhite.Println("\nAffected Configurations:")
							cblue("\n\tConfiguration 1:\n")
							for _, configurations := range vulnerability.CVE.Configurations {
								for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
									fmt.Printf("\t  %v\n", cpeMatch.Criteria)
									if len(cpeMatch.VersStartIncl) > 0 {
										cwhite("\t\tFrom (including): ")
										fmt.Printf("%v\n", cpeMatch.VersStartIncl)
									} else if len(cpeMatch.VersStartExcl) > 0 {
										cwhite("\t\tFrom (excluding): ")
										fmt.Printf("%v\n", cpeMatch.VersStartExcl)
									}
									if len(cpeMatch.VersEndInclud) > 0 {
										cwhite("\t\tUp to (including): ")
										fmt.Printf("%v\n", cpeMatch.VersEndInclud)
									} else if len(cpeMatch.VersEndExlud) > 0 {
										cwhite("\t\tUp to (excluding): ")
										fmt.Printf("%v\n", cpeMatch.VersEndExlud)
									}
								}
							}
							color.Cyan("\t-----RUNNING ON/WITH-----")
							for _, cpeMatch := range vulnerability.CVE.Configurations[0].Nodes[1].CpeMatch {
								fmt.Printf("\t  %v\n", cpeMatch.Criteria)
								if len(cpeMatch.VersStartIncl) > 0 {
									cwhite("\t\tFrom (including): ")
									fmt.Printf("%v\n", cpeMatch.VersStartIncl)
								} else if len(cpeMatch.VersStartExcl) > 0 {
									cwhite("\t\tFrom (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersStartExcl)
								}
								if len(cpeMatch.VersEndInclud) > 0 {
									cwhite("\t\tUp to (including): ")
									fmt.Printf("%v\n", cpeMatch.VersEndInclud)
								} else if len(cpeMatch.VersEndExlud) > 0 {
									cwhite("\t\tUp to (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersEndExlud)
								}
							}
						}
					}

				} else if len(vulnerability.CVE.Configurations) > 1 {
					boldWhite.Println("\nAffected Configurations:")
					for i, config := range vulnerability.CVE.Configurations {
						if config.Operator == "AND" {
							cblue("\n\tConfiguration %v:\n", i+1)
							if len(config.Nodes) > 1 {
								for i, node := range config.Nodes {
									if node.Operator == "OR" {
										if len(node.CpeMatch) <= 1 {
											for _, cpeMatch := range node.CpeMatch {
												fmt.Printf("\t  %v\n", cpeMatch.Criteria)
												if len(cpeMatch.VersStartIncl) > 0 {
													cwhite("\t\tFrom (including): ")
													fmt.Printf("%v\n", cpeMatch.VersStartIncl)
												} else if len(cpeMatch.VersStartExcl) > 0 {
													cwhite("\t\tFrom (excluding): ")
													fmt.Printf("%v\n", cpeMatch.VersStartExcl)
												}
												if len(cpeMatch.VersEndInclud) > 0 {
													cwhite("\t\tUp to (including): ")
													fmt.Printf("%v\n", cpeMatch.VersEndInclud)
												} else if len(cpeMatch.VersEndExlud) > 0 {
													cwhite("\t\tUp to (excluding): ")
													fmt.Printf("%v\n", cpeMatch.VersEndExlud)
												}
												if i < len(node.CpeMatch)-1 {
													color.Cyan("\t  -----RUNNING ON/WITH-----")
												} else if len(config.Nodes) == 2 && i == 0 {
													color.Cyan("\t  -----RUNNING ON/WITH-----")
												}
											}
										} else if len(node.CpeMatch) > 1 {
											for _, cpeMatch := range node.CpeMatch {
												fmt.Printf("\t  %v\n", cpeMatch.Criteria)
												if len(cpeMatch.VersStartIncl) > 0 {
													cwhite("\t\tFrom (including): ")
													fmt.Printf("%v\n", cpeMatch.VersStartIncl)
												} else if len(cpeMatch.VersStartExcl) > 0 {
													cwhite("\t\tFrom (excluding): ")
													fmt.Printf("%v\n", cpeMatch.VersStartExcl)
												}
												if len(cpeMatch.VersEndInclud) > 0 {
													cwhite("\t\tUp to (including): ")
													fmt.Printf("%v\n", cpeMatch.VersEndInclud)
												} else if len(cpeMatch.VersEndExlud) > 0 {
													cwhite("\t\tUp to (excluding): ")
													fmt.Printf("%v\n", cpeMatch.VersEndExlud)
												}
											}
											color.Cyan("\t  -----RUNNING ON/WITH-----")
										}
									}

								}
							} else if len(config.Nodes) == 1 {
								for _, node := range config.Nodes {
									if node.Operator == "OR" {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
										}
									}
								}
							}
						} else if config.Operator == "" {
							cblue("\n\tConfiguration %v:\n", i+1)
							if len(config.Nodes) > 1 {
								for i, node := range config.Nodes {
									if node.Operator == "OR" {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
											if i < len(node.CpeMatch)-1 {
												color.Cyan("\t  -----RUNNING ON/WITH-----")
											} else if len(config.Nodes) == 2 && i == 0 {
												color.Cyan("\t  -----RUNNING ON/WITH-----")
											}
										}
									}
								}
							} else if len(config.Nodes) == 1 {
								for _, node := range config.Nodes {
									if node.Operator == "OR" {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
										}
									} else if node.Operator == "AND" {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
										}
									}
								}
							}
						}
					}
				}
			}

			if len(vulnerability.CVE.References) > 0 {
				boldWhite.Println("\nReferences:")
				for _, reference := range vulnerability.CVE.References {
					if reference.Tags == nil {
						cwhite("\tURL: ")
						color.HiBlue("%v\n", reference.Url)
					} else if reference.Tags != nil {
						cwhite("\tURL: ")
						color.HiBlue("%v\n", reference.Url)
						fmt.Printf("\t\t%v %v\n", color.YellowString("Resource:"), reference.Tags)
					}
				}
			}

			fmt.Println("\n-----------------------------------")

			if o != "" {
				filename := o + ".csv"
				err = writecsv.WriteCSV(filename, nvdResponse.Vulnerabilities)
				if err != nil {
					color.Red("\nError writing to CSV:", err)
				} else {
					fmt.Printf("\nCSV file created: ")
					color.HiGreen("%v.csv\n\n", o)
					fmt.Println("-----------------------------------")
				}
			}
		}
	} else {
		fmt.Println("\n-----------------------------------")
		red("\nNo vulnerabilities found for: ")
		fmt.Printf("%v\n", c)
		fmt.Println("\n-----------------------------------")
	}
}

func Vulns(v []nvdstructs.Vulnerability) {
	whitep := color.New(color.FgWhite)
	boldWhite := whitep.Add(color.Bold)
	cwhite := color.New(color.FgHiWhite).PrintfFunc()
	cblue := color.New(color.FgBlue).PrintfFunc()

	for _, vulnerability := range v {
		boldWhite.Printf("CVE ID: ")
		fmt.Printf("%v\n", vulnerability.CVE.CVEID)
		publishedTime, err := time.Parse("2006-01-02T15:04:05.000", vulnerability.CVE.Published)
		if err == nil {
			publishedDate := publishedTime.Format("2006-01-02")
			boldWhite.Printf("\nPublished Date: ")
			fmt.Printf("%v\n", publishedDate)
		}

		lastModifiedTime, err := time.Parse("2006-01-02T15:04:05.000", vulnerability.CVE.LastModified)
		if err == nil {
			lastModifiedDate := lastModifiedTime.Format("2006-01-02")
			boldWhite.Printf("Last Modified Date: ")
			fmt.Printf("%v\n", lastModifiedDate)
		}
		if len(vulnerability.CVE.Metrics.CvssMetricV2) > 0 {
			for _, cvssv2 := range vulnerability.CVE.Metrics.CvssMetricV2 {
				boldWhite.Printf("\nCVSSv2 Type: ")
				fmt.Printf("%v\n", cvssv2.Type)
				boldWhite.Printf("CVSSv2 Source: ")
				fmt.Printf("%v\n", cvssv2.Source)
				boldWhite.Printf("\tSeverity: ")
				fmt.Printf("%v\n", cvssv2.BaseSev)
				boldWhite.Printf("\tBase Score: ")
				fmt.Printf("%v\n", cvssv2.CvssData.BaseScore)
				boldWhite.Printf("\tVector: ")
				fmt.Printf("%v\n", cvssv2.CvssData.Vector)
				boldWhite.Printf("\tImpact Score: ")
				fmt.Printf("%v\n", cvssv2.ImpactScore)
				boldWhite.Printf("\tExploitability Score: ")
				fmt.Printf("%v\n", cvssv2.ExplScore)
			}
		}

		if len(vulnerability.CVE.Metrics.CvssMetricV31) > 0 {
			for _, cvssv3 := range vulnerability.CVE.Metrics.CvssMetricV31 {
				boldWhite.Printf("\nCVSSv3 Type: ")
				fmt.Printf("%v\n", cvssv3.Type)
				boldWhite.Printf("CVSSv3 Source: ")
				fmt.Printf("%v\n", cvssv3.Source)
				boldWhite.Printf("\tSeverity: ")
				fmt.Printf("%v\n", cvssv3.CvssData.BaseSeverity)
				boldWhite.Printf("\tBase Score: ")
				fmt.Printf("%v\n", cvssv3.CvssData.BaseScore)
				boldWhite.Printf("\tVector: ")
				fmt.Printf("%v\n", cvssv3.CvssData.Vector)
				boldWhite.Printf("\tImpact Score: ")
				fmt.Printf("%v\n", cvssv3.ImpScore)
				boldWhite.Printf("\tExploitability Score: ")
				fmt.Printf("%v\n", cvssv3.ExplScore)
			}
		}

		if len(vulnerability.CVE.Configurations) > 0 {
			if len(vulnerability.CVE.Configurations) <= 1 {
				if vulnerability.CVE.Configurations[0].Operator == "" {
					if len(vulnerability.CVE.Configurations[0].Nodes) == 1 && vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
						boldWhite.Println("\nAffected Configurations:")
						cblue("\n\tConfiguration 1:\n")
						for _, configurations := range vulnerability.CVE.Configurations {
							for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
								fmt.Printf("\t  %v\n", cpeMatch.Criteria)
								if len(cpeMatch.VersStartIncl) > 0 {
									cwhite("\t\tFrom (including): ")
									fmt.Printf("%v\n", cpeMatch.VersStartIncl)
								} else if len(cpeMatch.VersStartExcl) > 0 {
									cwhite("\t\tFrom (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersStartExcl)
								}
								if len(cpeMatch.VersEndInclud) > 0 {
									cwhite("\t\tUp to (including): ")
									fmt.Printf("%v\n", cpeMatch.VersEndInclud)
								} else if len(cpeMatch.VersEndExlud) > 0 {
									cwhite("\t\tUp to (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersEndExlud)
								}
							}
						}
					}
				} else if vulnerability.CVE.Configurations[0].Operator == "AND" {
					if vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
						boldWhite.Println("\nAffected Configurations:")
						cblue("\n\tConfiguration 1:\n")
						for _, configurations := range vulnerability.CVE.Configurations {
							for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
								fmt.Printf("\t  %v\n", cpeMatch.Criteria)
								if len(cpeMatch.VersStartIncl) > 0 {
									cwhite("\t\tFrom (including): ")
									fmt.Printf("%v\n", cpeMatch.VersStartIncl)
								} else if len(cpeMatch.VersStartExcl) > 0 {
									cwhite("\t\tFrom (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersStartExcl)
								}
								if len(cpeMatch.VersEndInclud) > 0 {
									cwhite("\t\tUp to (including): ")
									fmt.Printf("%v\n", cpeMatch.VersEndInclud)
								} else if len(cpeMatch.VersEndExlud) > 0 {
									cwhite("\t\tUp to (excluding): ")
									fmt.Printf("%v\n", cpeMatch.VersEndExlud)
								}
							}
						}
						color.Cyan("\t-----RUNNING ON/WITH-----")
						for _, cpeMatch := range vulnerability.CVE.Configurations[0].Nodes[1].CpeMatch {
							fmt.Printf("\t  %v\n", cpeMatch.Criteria)
							if len(cpeMatch.VersStartIncl) > 0 {
								cwhite("\t\tFrom (including): ")
								fmt.Printf("%v\n", cpeMatch.VersStartIncl)
							} else if len(cpeMatch.VersStartExcl) > 0 {
								cwhite("\t\tFrom (excluding): ")
								fmt.Printf("%v\n", cpeMatch.VersStartExcl)
							}
							if len(cpeMatch.VersEndInclud) > 0 {
								cwhite("\t\tUp to (including): ")
								fmt.Printf("%v\n", cpeMatch.VersEndInclud)
							} else if len(cpeMatch.VersEndExlud) > 0 {
								cwhite("\t\tUp to (excluding): ")
								fmt.Printf("%v\n", cpeMatch.VersEndExlud)
							}
						}
					}
				}

			} else if len(vulnerability.CVE.Configurations) > 1 {
				boldWhite.Println("\nAffected Configurations:")
				for i, config := range vulnerability.CVE.Configurations {
					if config.Operator == "AND" {
						cblue("\n\tConfiguration %v:\n", i+1)
						if len(config.Nodes) > 1 {
							for i, node := range config.Nodes {
								if node.Operator == "OR" {
									if len(node.CpeMatch) <= 1 {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
											if i < len(node.CpeMatch)-1 {
												color.Cyan("\t  -----RUNNING ON/WITH-----")
											} else if len(config.Nodes) == 2 && i == 0 {
												color.Cyan("\t  -----RUNNING ON/WITH-----")
											}
										}
									} else if len(node.CpeMatch) > 1 {
										for _, cpeMatch := range node.CpeMatch {
											fmt.Printf("\t  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												cwhite("\t\tFrom (including): ")
												fmt.Printf("%v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												cwhite("\t\tFrom (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												cwhite("\t\tUp to (including): ")
												fmt.Printf("%v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												cwhite("\t\tUp to (excluding): ")
												fmt.Printf("%v\n", cpeMatch.VersEndExlud)
											}
										}
										color.Cyan("\t  -----RUNNING ON/WITH-----")
									}
								}

							}
						} else if len(config.Nodes) == 1 {
							for _, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("\t  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											cwhite("\t\tFrom (including): ")
											fmt.Printf("%v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											cwhite("\t\tFrom (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											cwhite("\t\tUp to (including): ")
											fmt.Printf("%v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											cwhite("\t\tUp to (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersEndExlud)
										}
									}
								}
							}
						}
					} else if config.Operator == "" {
						cblue("\n\tConfiguration %v:\n", i+1)
						if len(config.Nodes) > 1 {
							for i, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("\t  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											cwhite("\t\tFrom (including): ")
											fmt.Printf("%v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											cwhite("\t\tFrom (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											cwhite("\t\tUp to (including): ")
											fmt.Printf("%v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											cwhite("\t\tUp to (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersEndExlud)
										}
										if i < len(node.CpeMatch)-1 {
											color.Cyan("\t  -----RUNNING ON/WITH-----")
										} else if len(config.Nodes) == 2 && i == 0 {
											color.Cyan("\t  -----RUNNING ON/WITH-----")
										}
									}
								}
							}
						} else if len(config.Nodes) == 1 {
							for _, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("\t  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											cwhite("\t\tFrom (including): ")
											fmt.Printf("%v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											cwhite("\t\tFrom (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											cwhite("\t\tUp to (including): ")
											fmt.Printf("%v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											cwhite("\t\tUp to (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersEndExlud)
										}
									}
								} else if node.Operator == "AND" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("\t  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											cwhite("\t\tFrom (including): ")
											fmt.Printf("%v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											cwhite("\t\tFrom (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											cwhite("\t\tUp to (including): ")
											fmt.Printf("%v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											cwhite("\t\tUp to (excluding): ")
											fmt.Printf("%v\n", cpeMatch.VersEndExlud)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if len(vulnerability.CVE.References) > 0 {
			boldWhite.Println("\nReferences:")
			for _, reference := range vulnerability.CVE.References {
				if reference.Tags == nil {
					cwhite("\tURL: ")
					color.HiBlue("%v\n", reference.Url)
				} else if reference.Tags != nil {
					cwhite("\tURL: ")
					color.HiBlue("%v\n", reference.Url)
					fmt.Printf("\t\t%v %v\n", color.YellowString("Resource:"), reference.Tags)
				}
			}
		}
		fmt.Println("\n-----------------------------------")
	}
}
