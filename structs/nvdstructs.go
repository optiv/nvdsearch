package nvdstructs

type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	CPEversion      string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVEInfo `json:"cve"`
}

type CVEInfo struct {
	CVEID          string           `json:"id"`
	Source         string           `json:"sourceIdentifier"`
	Published      string           `json:"published"`
	LastModified   string           `json:"lastModified"`
	VulnStatus     string           `json:"vulnStatus"`
	Descriptions   []Descriptions   `json:"descriptions"`
	Metrics        Metrics          `json:"metrics"`
	Weaknesses     []Weaknesses     `json:"weaknesses"`
	Configurations []Configurations `json:"configurations"`
	References     []References     `json:"references"`
}

type Descriptions struct {
	Language string `json:"lang"`
	Value    string `json:"value"`
}

type Metrics struct {
	CvssMetricV2  []CvssMetricV2  `json:"cvssMetricV2"`
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31`
}

type CvssMetricV2 struct {
	Source       string     `json:"source"`
	Type         string     `json:"type"`
	CvssData     CvssDataV2 `json:"cvssData"`
	BaseSev      string     `json:"baseSeverity"`
	ExplScore    float64    `json:"exploitabilityScore"`
	ImpactScore  float64    `json:"impactScore"`
	AcInsufInfo  bool       `json:"acInsufInfo"`
	ObtAllPriv   bool       `json:"obtainAllPrivilege"`
	ObtUserPriv  bool       `json:"obtainUserPrivilege"`
	ObtOtherPriv bool       `json:"obtainOtherPrivilege"`
	UserIntReqd  bool       `json:"userInteractionRequired"`
}

type CvssDataV2 struct {
	Version          string  `json:"version"`
	Vector           string  `json:"vectorString"`
	AccessVector     string  `json:"accessVector"`
	AccessComplexity string  `json:"accessComplexity"`
	Authentication   string  `json:"authentication"`
	ConfImpact       string  `json:"confidentialityImpact"`
	IntegrityImpact  string  `json:"integrityImpact"`
	AvailImpact      string  `json:"availabilityImpact"`
	BaseScore        float64 `json:"baseScore"`
}

type CvssMetricV31 struct {
	Source    string      `json:"source"`
	Type      string      `json:"type"`
	CvssData  CvssDataV31 `json:"cvssData"`
	ExplScore float64     `json:"exploitabilityScore"`
	ImpScore  float64     `json:"impactScore"`
}

type CvssDataV31 struct {
	Version          string  `json:"version"`
	Vector           string  `json:"vectorString"`
	AttackVector     string  `json:"attackVector"`
	AttackComplexity string  `json:"attackComplexity"`
	PrivRequired     string  `json:"privilegesRequired"`
	UserInteraction  string  `json:"userInteraction"`
	Scope            string  `json:"scope"`
	ConfImpact       string  `json:"confidentialityImpact"`
	IntegrityImpact  string  `json:"integrityImpact"`
	AvailImpact      string  `json:"availabilityImpact"`
	BaseScore        float64 `json:"baseScore"`
	BaseSeverity     string  `json:"baseSeverity"`
}

type Weaknesses struct {
	Source      string         `json:"source"`
	Type        string         `json:"type"`
	Description []WDescription `json:"description"`
}

type WDescription struct {
	Lang string `json:"lang"`
	Val  string `json:"value"`
}

type Configurations struct {
	Operator string  `json:"operator"`
	Nodes    []Nodes `json:"nodes"`
}

type Nodes struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []CpeMatch `json:"cpeMatch"`
}

type CpeMatch struct {
	Vulnerable      bool   `json:"vulnerable"`
	Criteria        string `json:"criteria"`
	VersStartIncl   string `json:"versionStartIncluding"`
	VersStartExcl   string `json:"versionStartExcluding"`
	VersEndInclud   string `json:"versionEndIncluding"`
	VersEndExlud    string `json:"versionEndExcluding"`
	MatchCriteriaID string `json:"matchCriteriaId"`
}

type References struct {
	Url    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type SearchResponse struct {
	ResultsPerPage int        `json:"resultsPerPage"`
	StartIndex     int        `json:"startIndex"`
	TotalResults   int        `json:"totalResults"`
	Format         string     `json:"format"`
	CPEversion     string     `json:"version"`
	Timestamp      string     `json:"timestamp"`
	Products       []Products `json:"products"`
}

type Products struct {
	CPE CpeList `json:"cpe"`
}

type CpeList struct {
	Deprecated   bool     `json:"deprecated"`
	CpeName      string   `json:"cpeName"`
	CpeNameID    string   `json:"cpeNameId"`
	LastModified string   `json:"lastModified"`
	Created      string   `json:"created"`
	Titles       []Titles `json:"titles"`
}

type Titles struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}
