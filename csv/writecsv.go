package writecsv

import (
	"encoding/csv"
	"fmt"
	nvdstructs "nvdsearch/structs"
	"os"
	"strconv"
	"strings"
)

func WriteProdCSV(f string, products []nvdstructs.Products) error {
	file, err := os.Create(f)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	header := []string{"Title", "CPE Name", "CPE ID", "Created", "Last Modified", "Deprecated"}
	err = writer.Write(header)
	if err != nil {
		return err
	}

	for _, products := range products {
		dep := "false"
		if products.CPE.Deprecated {
			dep = "true"
		}
		row := []string{
			products.CPE.Titles[0].Title,
			products.CPE.CpeName,
			products.CPE.CpeNameID,
			products.CPE.Created,
			products.CPE.LastModified,
			dep,
		}
		err = writer.Write(row)
		if err != nil {
			return err
		}
	}

	writer.Flush()

	return writer.Error()
}

func WriteAddProdCSV(f string, products []nvdstructs.Products) error {
	file, err := os.OpenFile(f, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	for _, product := range products {
		dep := "false"
		if product.CPE.Deprecated {
			dep = "true"
		}
		row := []string{
			product.CPE.Titles[0].Title,
			product.CPE.CpeName,
			product.CPE.CpeNameID,
			product.CPE.Created,
			product.CPE.LastModified,
			dep,
		}
		err = writer.Write(row)
		if err != nil {
			return err
		}
	}

	writer.Flush()

	return writer.Error()
}

func WriteCSV(f string, vulnerabilities []nvdstructs.Vulnerability) error {
	file, err := os.Create(f)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	header := []string{"CVE ID", "Published Date", "Last Modified Date", "Vuln Status", "Description"}

	cvssV2Headers := []string{"CVSSv2 Type", "CVSSv2 Source", "CVSSv2 Base Severity", "CVSSv2 Base Score", "CVSSv2 Exploitability Score", "CVSSv2 Impact Score", "CVSSv2 Vector String", "CVSSv2 Access Vector", "CVSSv2 Access Complexity", "CVSSv2 Authentication", "CVSSv2 Confidentiality Impact", "CVSSv2 Integrity Impact", "CVSSv2 Availability Impact"}

	cvssV3Headers := []string{"CVSSv3 Type", "CVSSv3 Source", "CVSSv3 Base Severity", "CVSSv3 Base Score", "CVSSv3 Exploitability Score", "CVSSv3 Impact Score", "CVSSv3 Vector String", "CVSSv3 Attack Vector", "CVSSv3 Attack Complexity", "CVSSv3 Privileges Required", "CVSSv3 User Interaction", "CVSSv3 Scope", "CVSSv3 Confidentiality Impact", "CVSSv3 Integrity Impact", "CVSSv3 Availability Impact"}

	for i := 1; i <= getMaxCVSSv2MetricCount(vulnerabilities); i++ {
		header = append(header, cvssV2Headers...)
	}

	for i := 1; i <= getMaxCVSSv3MetricCount(vulnerabilities); i++ {
		header = append(header, cvssV3Headers...)
	}

	header = append(header, "Weakness Type")
	header = append(header, "Affected Configurations")
	header = append(header, "References")

	err = writer.Write(header)
	if err != nil {
		return err
	}

	maxCVSSv2MetricCount := getMaxCVSSv2MetricCount(vulnerabilities)
	maxCVSSv3MetricCount := getMaxCVSSv3MetricCount(vulnerabilities)

	for _, vulnerability := range vulnerabilities {
		var row []string
		row = append(row, vulnerability.CVE.CVEID)
		row = append(row, vulnerability.CVE.Published)
		row = append(row, vulnerability.CVE.LastModified)
		row = append(row, vulnerability.CVE.VulnStatus)
		for _, description := range vulnerability.CVE.Descriptions {
			if description.Language == "en" {
				row = append(row, description.Value)
				break
			}
		}

		for i := 0; i < maxCVSSv2MetricCount; i++ {
			if i < len(vulnerability.CVE.Metrics.CvssMetricV2) {
				cvssMetric := vulnerability.CVE.Metrics.CvssMetricV2[i]
				row = append(row, cvssMetric.Type)
				row = append(row, cvssMetric.Source)
				row = append(row, cvssMetric.BaseSev)
				row = append(row, strconv.FormatFloat(cvssMetric.CvssData.BaseScore, 'f', -1, 64))
				row = append(row, strconv.FormatFloat(cvssMetric.ExplScore, 'f', -1, 64))
				row = append(row, strconv.FormatFloat(cvssMetric.ImpactScore, 'f', -1, 64))
				row = append(row, cvssMetric.CvssData.Vector)
				row = append(row, cvssMetric.CvssData.AccessVector)
				row = append(row, cvssMetric.CvssData.AccessComplexity)
				row = append(row, cvssMetric.CvssData.Authentication)
				row = append(row, cvssMetric.CvssData.ConfImpact)
				row = append(row, cvssMetric.CvssData.IntegrityImpact)
				row = append(row, cvssMetric.CvssData.AvailImpact)
			} else {
				row = append(row, makeEmptyCVSSv2Metrics()...)
			}
		}

		for i := 0; i < maxCVSSv3MetricCount; i++ {
			if i < len(vulnerability.CVE.Metrics.CvssMetricV31) {
				cvssMetric := vulnerability.CVE.Metrics.CvssMetricV31[i]
				row = append(row, cvssMetric.Type)
				row = append(row, cvssMetric.Source)
				row = append(row, cvssMetric.CvssData.BaseSeverity)
				row = append(row, strconv.FormatFloat(cvssMetric.CvssData.BaseScore, 'f', -1, 64))
				row = append(row, strconv.FormatFloat(cvssMetric.ExplScore, 'f', -1, 64))
				row = append(row, strconv.FormatFloat(cvssMetric.ImpScore, 'f', -1, 64))
				row = append(row, cvssMetric.CvssData.Vector)
				row = append(row, cvssMetric.CvssData.AttackVector)
				row = append(row, cvssMetric.CvssData.AttackComplexity)
				row = append(row, cvssMetric.CvssData.PrivRequired)
				row = append(row, cvssMetric.CvssData.UserInteraction)
				row = append(row, cvssMetric.CvssData.Scope)
				row = append(row, cvssMetric.CvssData.ConfImpact)
				row = append(row, cvssMetric.CvssData.IntegrityImpact)
				row = append(row, cvssMetric.CvssData.AvailImpact)
			} else {
				row = append(row, makeEmptyCVSSv3Metrics()...)
			}
		}

		weaknesses := make(map[string]bool)
		for _, weakness := range vulnerability.CVE.Weaknesses {
			weaknessType := weakness.Description[0].Val
			weaknesses[weaknessType] = true
		}
		var uniqueWeaknesses []string
		for weaknessType := range weaknesses {
			uniqueWeaknesses = append(uniqueWeaknesses, weaknessType)
		}
		row = append(row, strings.Join(uniqueWeaknesses, "\n"))

		var output string
		if len(vulnerability.CVE.Configurations) > 0 {
			if len(vulnerability.CVE.Configurations) <= 1 {
				if vulnerability.CVE.Configurations[0].Operator == "" {
					if len(vulnerability.CVE.Configurations[0].Nodes) == 1 && vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
						output += "Configuration 1:\n"
						for _, configurations := range vulnerability.CVE.Configurations {
							for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
								output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
								if len(cpeMatch.VersStartIncl) > 0 {
									output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
								} else if len(cpeMatch.VersStartExcl) > 0 {
									output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
								}
								if len(cpeMatch.VersEndInclud) > 0 {
									output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
								} else if len(cpeMatch.VersEndExlud) > 0 {
									output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
								}
							}
						}
					}
				} else if vulnerability.CVE.Configurations[0].Operator == "AND" {
					if vulnerability.CVE.Configurations[0].Nodes[0].Operator == "OR" {
						output += "Configuration 1:\n"
						for _, configurations := range vulnerability.CVE.Configurations {
							for _, cpeMatch := range configurations.Nodes[0].CpeMatch {
								output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
								if len(cpeMatch.VersStartIncl) > 0 {
									output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
								} else if len(cpeMatch.VersStartExcl) > 0 {
									output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
								}
								if len(cpeMatch.VersEndInclud) > 0 {
									output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
								} else if len(cpeMatch.VersEndExlud) > 0 {
									output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
								}
							}
						}
						output += "  -----RUNNING ON/WITH-----\n"
						for _, cpeMatch := range vulnerability.CVE.Configurations[0].Nodes[1].CpeMatch {
							output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
							if len(cpeMatch.VersStartIncl) > 0 {
								output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
							} else if len(cpeMatch.VersStartExcl) > 0 {
								output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
							}
							if len(cpeMatch.VersEndInclud) > 0 {
								output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
							} else if len(cpeMatch.VersEndExlud) > 0 {
								output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
							}
						}
					}
				}

			} else if len(vulnerability.CVE.Configurations) > 1 {
				for i, config := range vulnerability.CVE.Configurations {
					if config.Operator == "AND" {
						output += fmt.Sprintf("Configuration %v:\n", i+1)
						if len(config.Nodes) > 1 {
							for i, node := range config.Nodes {
								if node.Operator == "OR" {
									if len(node.CpeMatch) <= 1 {
										for _, cpeMatch := range node.CpeMatch {
											output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
											}
											if i < len(node.CpeMatch)-1 {
												output += "  -----RUNNING ON/WITH-----\n"
											} else if len(config.Nodes) == 2 && i == 0 {
												output += "  -----RUNNING ON/WITH-----\n"
											}
										}
									} else if len(node.CpeMatch) > 1 {
										for _, cpeMatch := range node.CpeMatch {
											output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
											if len(cpeMatch.VersStartIncl) > 0 {
												output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
											} else if len(cpeMatch.VersStartExcl) > 0 {
												output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
											}
											if len(cpeMatch.VersEndInclud) > 0 {
												output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
											} else if len(cpeMatch.VersEndExlud) > 0 {
												output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
											}
										}
										output += "  -----RUNNING ON/WITH-----\n"
									}
								}

							}
						} else if len(config.Nodes) == 1 {
							for _, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
										}
									}
								}
							}
						}
					} else if config.Operator == "" {
						output += fmt.Sprintf("Configuration %v:\n", i+1)
						if len(config.Nodes) > 1 {
							for i, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
										}
										if i < len(node.CpeMatch)-1 {
											output += "\n  -----RUNNING ON/WITH-----\n"
										} else if len(config.Nodes) == 2 && i == 0 {
											output += "\n  -----RUNNING ON/WITH-----\n"
										}
									}
								}
							}
						} else if len(config.Nodes) == 1 {
							for _, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpeMatch := range node.CpeMatch {
										output += fmt.Sprintf("  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
										}
									}
								} else if node.Operator == "AND" {
									for _, cpeMatch := range node.CpeMatch {
										fmt.Printf("\t  %v\n", cpeMatch.Criteria)
										if len(cpeMatch.VersStartIncl) > 0 {
											output += fmt.Sprintf("\tFrom (including): %v\n", cpeMatch.VersStartIncl)
										} else if len(cpeMatch.VersStartExcl) > 0 {
											output += fmt.Sprintf("\tFrom (excluding): %v\n", cpeMatch.VersStartExcl)
										}
										if len(cpeMatch.VersEndInclud) > 0 {
											output += fmt.Sprintf("\tUp to (including): %v\n", cpeMatch.VersEndInclud)
										} else if len(cpeMatch.VersEndExlud) > 0 {
											output += fmt.Sprintf("\tUp to (excluding): %v\n", cpeMatch.VersEndExlud)
										}
									}
								}
							}
						}
					}
				}
			}
		}
		row = append(row, output)

		var ref string
		if len(vulnerability.CVE.References) > 0 {
			for _, reference := range vulnerability.CVE.References {
				if reference.Tags == nil {
					ref += fmt.Sprintf("%v\n", reference.Url)
				} else if reference.Tags != nil {
					ref += fmt.Sprintf("%v,%v\n", reference.Url, reference.Tags)
				}
			}
		}
		row = append(row, ref)

		err = writer.Write(row)
		if err != nil {
			return err
		}
	}

	writer.Flush()

	return writer.Error()
}

func getMaxCVSSv2MetricCount(vulnerabilities []nvdstructs.Vulnerability) int {
	maxCount := 0
	for _, vulnerability := range vulnerabilities {
		count := len(vulnerability.CVE.Metrics.CvssMetricV2)
		if count > maxCount {
			maxCount = count
		}
	}
	return maxCount
}

func getMaxCVSSv3MetricCount(vulnerabilities []nvdstructs.Vulnerability) int {
	maxCount := 0
	for _, vulnerability := range vulnerabilities {
		count := len(vulnerability.CVE.Metrics.CvssMetricV31)
		if count > maxCount {
			maxCount = count
		}
	}
	return maxCount
}

func makeEmptyCVSSv2Metrics() []string {
	return []string{"", "", "", "", "", "", "", "", "", "", "", "", ""}
}

func makeEmptyCVSSv3Metrics() []string {
	return []string{"", "", "", "", "", "", "", "", "", "", "", "", "", "", ""}
}
