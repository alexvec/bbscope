package hackerone

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sw33tLie/bbscope/internal/utils"
	"github.com/sw33tLie/bbscope/pkg/scope"
	"github.com/sw33tLie/bbscope/pkg/whttp"
	"github.com/tidwall/gjson"
)

const (
	RATE_LIMIT_WAIT_TIME_SEC = 5
	RATE_LIMIT_MAX_RETRIES   = 50
	RATE_LIMIT_HTTP_STATUS   = 429
)

type Program struct {
	ID         string `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	Attributes struct {
		Handle                          string    `json:"handle,omitempty"`
		Name                            string    `json:"name,omitempty"`
		Currency                        string    `json:"currency,omitempty"`
		ProfilePicture                  string    `json:"profile_picture,omitempty"`
		SubmissionState                 string    `json:"submission_state,omitempty"`
		TriageActive                    any       `json:"triage_active,omitempty"`
		State                           string    `json:"state,omitempty"`
		StartedAcceptingAt              time.Time `json:"started_accepting_at,omitempty"`
		NumberOfReportsForUser          int       `json:"number_of_reports_for_user,omitempty"`
		NumberOfValidReportsForUser     int       `json:"number_of_valid_reports_for_user,omitempty"`
		BountyEarnedForUser             float64   `json:"bounty_earned_for_user,omitempty"`
		LastInvitationAcceptedAtForUser any       `json:"last_invitation_accepted_at_for_user,omitempty"`
		Bookmarked                      bool      `json:"bookmarked,omitempty"`
		AllowsBountySplitting           bool      `json:"allows_bounty_splitting,omitempty"`
		OffersBounties                  bool      `json:"offers_bounties,omitempty"`
	} `json:"attributes,omitempty"`
	Relationships struct {
		StructuredScopes struct {
			Data []struct {
				ID         string `json:"id,omitempty"`
				Type       string `json:"type,omitempty"`
				Attributes struct {
					AssetType                  string    `json:"asset_type,omitempty"`
					AssetIdentifier            string    `json:"asset_identifier,omitempty"`
					EligibleForBounty          bool      `json:"eligible_for_bounty,omitempty"`
					EligibleForSubmission      bool      `json:"eligible_for_submission,omitempty"`
					Instruction                string    `json:"instruction,omitempty"`
					MaxSeverity                string    `json:"max_severity,omitempty"`
					Reference                  string    `json:"reference,omitempty"`
					CreatedAt                  time.Time `json:"created_at,omitempty"`
					UpdatedAt                  time.Time `json:"updated_at,omitempty"`
					ConfidentialityRequirement string    `json:"confidentiality_requirement,omitempty"`
					IntegrityRequirement       string    `json:"integrity_requirement,omitempty"`
					AvailabilityRequirement    string    `json:"availability_requirement,omitempty"`
				} `json:"attributes,omitempty"`
			} `json:"data,omitempty"`
		} `json:"structured_scopes,omitempty"`
	} `json:"relationships,omitempty"`
}

func getProgramScope(authorization string, id string, bbpOnly bool, categories []string) (pData scope.ProgramData) {
	r, err := regexp.Compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]")
	if err != nil {
		utils.Log.Fatal("Could not create regex pattern for id ", id)
	}
	res := &whttp.WHTTPRes{}
	lastStatus := -1

	for i := 0; i < RATE_LIMIT_MAX_RETRIES; i++ {
		res, err = whttp.SendHTTPRequest(
			&whttp.WHTTPReq{
				Method: "GET",
				URL:    "https://api.hackerone.com/v1/hackers/programs/" + id,
				Headers: []whttp.WHTTPHeader{
					{Name: "Authorization", Value: "Basic " + authorization},
				},
			}, http.DefaultClient)

		if err != nil {
			utils.Log.Warn("HTTP request failed: ", err, " Retrying...")
			time.Sleep(2 * time.Second)
			continue
		}

		lastStatus = res.StatusCode
		// exit the loop if we succeeded
		if res.StatusCode != RATE_LIMIT_HTTP_STATUS {
			break
		} else {
			// encountered rate limit
			time.Sleep(RATE_LIMIT_WAIT_TIME_SEC * time.Second)
		}
	}
	if lastStatus != 200 {
		// if we completed the requests with a final (non-429) status and we still failed
		utils.Log.Fatal("Could not retrieve data for id ", id, " with status ", lastStatus)
	}

	pData.Url = "https://hackerone.com/" + id

	var program Program

	err = json.Unmarshal([]byte(res.BodyString), &program)

	if err != nil {
		utils.Log.Fatal("Could not parse program for id  ", id, " with status ", lastStatus)
	}

	l := len(program.Relationships.StructuredScopes.Data)

	isDumpAll := len(categories) == len(getCategories("all"))
	targets := make(map[string]struct{})
	for i := 0; i < l; i++ {

		catFound := false
		if !isDumpAll {
			assetCategory := program.Relationships.StructuredScopes.Data[i].Attributes.AssetType

			for _, cat := range categories {
				if cat == assetCategory {
					catFound = true
					break
				}
			}
		}

		if catFound || isDumpAll {
			// If it's in the in-scope table (and not in the OOS one)
			if program.Relationships.StructuredScopes.Data[i].Attributes.EligibleForSubmission {
				if !bbpOnly || (bbpOnly && program.Relationships.StructuredScopes.Data[i].Attributes.EligibleForBounty) {
					if program.Relationships.StructuredScopes.Data[i].Attributes.AssetType == "DOMAIN" || program.Relationships.StructuredScopes.Data[i].Attributes.AssetType == "URL" || program.Relationships.StructuredScopes.Data[i].Attributes.AssetType == "OTHER" || program.Relationships.StructuredScopes.Data[i].Attributes.AssetType == "WILDCARD" {
						for _, match := range r.FindAllString(strings.ToLower(program.Relationships.StructuredScopes.Data[i].Attributes.AssetIdentifier), -1) {
							_, ok := targets[match]
							if !ok {
								pData.InScope = append(pData.InScope, scope.ScopeElement{
									Target:      match,
									Description: strings.ReplaceAll(program.Relationships.StructuredScopes.Data[i].Attributes.Instruction, "\n", "  "),
									Category:    "", // TODO
								})
								targets[match] = struct{}{}
							}
						}
						for _, match := range r.FindAllString(strings.ToLower(program.Relationships.StructuredScopes.Data[i].Attributes.Instruction), -1) {
							_, ok := targets[match]
							if !ok {
								pData.InScope = append(pData.InScope, scope.ScopeElement{
									Target:      match,
									Description: strings.ReplaceAll(program.Relationships.StructuredScopes.Data[i].Attributes.Instruction, "\n", "  "),
									Category:    "", // TODO
								})
								targets[match] = struct{}{}
							}
						}
					} else {
						pData.InScope = append(pData.InScope, scope.ScopeElement{
							Target:      program.Relationships.StructuredScopes.Data[i].Attributes.AssetIdentifier,
							Description: strings.ReplaceAll(program.Relationships.StructuredScopes.Data[i].Attributes.Instruction, "\n", "  "),
							Category:    "", // TODO
						})
					}
				}
			}
		}
	}

	/*
		if l == 0 {
			pData.InScope = append(pData.InScope, scope.ScopeElement{Target: "NO_IN_SCOPE_TABLE", Description: "", Category: ""})
		}
	*/

	return pData
}

func getCategories(input string) []string {
	categories := map[string][]string{
		"domain":     {"DOMAIN"},
		"wildcard":   {"WILDCARD"},
		"url":        {"URL"},
		"cidr":       {"CIDR"},
		"mobile":     {"GOOGLE_PLAY_APP_ID", "OTHER_APK", "APPLE_STORE_APP_ID"},
		"android":    {"GOOGLE_PLAY_APP_ID", "OTHER_APK"},
		"apple":      {"APPLE_STORE_APP_ID"},
		"other":      {"OTHER"},
		"hardware":   {"HARDWARE"},
		"code":       {"SOURCE_CODE"},
		"executable": {"DOWNLOADABLE_EXECUTABLES"},
		"all":        {"DOMAIN", "WILDCARD", "URL", "CIDR", "GOOGLE_PLAY_APP_ID", "OTHER_APK", "APPLE_STORE_APP_ID", "OTHER", "HARDWARE", "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES"},
		"allinfra":   {"DOMAIN", "WILDCARD", "URL", "CIDR", "OTHER"},
	}

	selectedCategory, ok := categories[strings.ToLower(input)]
	if !ok {
		utils.Log.Fatal("Invalid category selected")
	}
	return selectedCategory
}

func getProgramHandles(authorization string, pvtOnly bool, publicOnly bool, active bool) (handles []string) {
	currentURL := "https://api.hackerone.com/v1/hackers/programs"
	for {
		res, err := whttp.SendHTTPRequest(
			&whttp.WHTTPReq{
				Method: "GET",
				URL:    currentURL,
				Headers: []whttp.WHTTPHeader{
					{Name: "Authorization", Value: "Basic " + authorization},
				},
			}, http.DefaultClient)

		if err != nil {
			utils.Log.Warn("HTTP request failed: ", err, " Retrying...")
			time.Sleep(2 * time.Second)
			continue
		}

		if res.StatusCode != 200 {
			utils.Log.Fatal("Fetching failed. Got status Code: ", res.StatusCode)
		}

		for i := 0; i < int(gjson.Get(res.BodyString, "data.#").Int()); i++ {
			handle := gjson.Get(res.BodyString, "data."+strconv.Itoa(i)+".attributes.handle")

			if !publicOnly {
				if !pvtOnly || (pvtOnly && gjson.Get(res.BodyString, "data."+strconv.Itoa(i)+".attributes.state").Str == "soft_launched") {
					if active {
						if gjson.Get(res.BodyString, "data."+strconv.Itoa(i)+".attributes.submission_state").Str == "open" {
							handles = append(handles, handle.Str)
						}
					} else {
						handles = append(handles, handle.Str)
					}
				}
			} else {
				if gjson.Get(res.BodyString, "data."+strconv.Itoa(i)+".attributes.state").Str == "public_mode" {
					if active {
						if gjson.Get(res.BodyString, "data."+strconv.Itoa(i)+".attributes.submission_state").Str == "open" {
							handles = append(handles, handle.Str)
						}
					} else {
						handles = append(handles, handle.Str)
					}
				}
			}
		}

		currentURL = gjson.Get(res.BodyString, "links.next").Str

		// We reached the end
		if currentURL == "" {
			break
		}
	}

	return handles
}

// GetAllProgramsScope xxx
func GetAllProgramsScope(authorization string, bbpOnly bool, pvtOnly bool, publicOnly bool, categories string, active bool, concurrency int) (programs []scope.ProgramData) {
	utils.Log.Debug("Fetching list of program handles")
	programHandles := getProgramHandles(authorization, pvtOnly, publicOnly, active)

	utils.Log.Debug("Fetching scope of each program. Concurrency: ", concurrency)
	ids := make(chan string, concurrency)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			for {
				id := <-ids

				if id == "" {
					break
				}

				programs = append(programs, getProgramScope(authorization, id, bbpOnly, getCategories(categories)))
			}
			processGroup.Done()
		}()
	}

	for _, s := range programHandles {
		ids <- s
	}

	close(ids)
	processGroup.Wait()

	return programs
}

// PrintAllScope prints to stdout all scope elements of all targets
func PrintAllScope(authorization string, bbpOnly bool, pvtOnly bool, publicOnly bool, categories string, outputFlags string, delimiter string, active bool, concurrency int) {
	programs := GetAllProgramsScope(authorization, bbpOnly, pvtOnly, publicOnly, categories, active, concurrency)
	for _, pData := range programs {
		scope.PrintProgramScope(pData, outputFlags, delimiter)
	}
}
