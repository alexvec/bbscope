package bugcrowd

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/sw33tLie/bbscope/internal/utils"
	"github.com/sw33tLie/bbscope/pkg/scope"
	"github.com/sw33tLie/bbscope/pkg/whttp"
	"github.com/tidwall/gjson"
)

const (
	USER_AGENT               = "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0"
	BUGCROWD_LOGIN_PAGE      = "https://bugcrowd.com/user/sign_in"
	RATE_LIMIT_SLEEP_SECONDS = 5
)

type Program struct {
	Targets []struct {
		ID          string `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		Category    string `json:"category,omitempty"`
		URI         string `json:"uri,omitempty"`
		IPAddress   string `json:"ipAddress,omitempty"`
	} `json:"targets,omitempty"`
}

func Login(email string, password string) string {
	// Send GET to https://bugcrowd.com/user/sign_in
	// Get _crowdcontrol_session_key cookie
	// Get <meta name="csrf-token" content="Da...ktOQ==" />
	// Still under development

	req, err := http.NewRequest("GET", BUGCROWD_LOGIN_PAGE, nil)
	if err != nil {
		utils.Log.Fatal(err)
	}

	req.Header.Set("User-Agent", USER_AGENT)
	client := &http.Client{
		// We don't need to follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	crowdControlSession := ""
	csrfToken := ""
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(cookie, "_crowdcontrol_session_key") {
			crowdControlSession = strings.Split(strings.Split(cookie, ";")[0], "=")[1]
			break
		}
	}

	if crowdControlSession == "" {
		utils.Log.Fatal("Failed to get cookie. Something might have changed")
	}

	// Now we need to get the csrf-token...HTML parsing here we go
	body, _ := ioutil.ReadAll(resp.Body)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))

	if err != nil {
		utils.Log.Fatal("Failed to parse login response")
	}

	doc.Find("meta").Each(func(index int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		if name == "csrf-token" {
			csrfToken, _ = s.Attr("content")
			//fmt.Println("TOKEN: ", url.QueryEscape(content))
		}
	})

	if csrfToken == "" {
		utils.Log.Fatal("Failed to get the CSRF token. Something might have changed")
	}

	// Now send the POST request
	req2, err := http.NewRequest("POST", BUGCROWD_LOGIN_PAGE, bytes.NewBuffer([]byte("utf8=%E2%9C%93&authenticity_token="+url.QueryEscape(csrfToken)+"&user%5Bredirect_to%5D=&user%5Bemail%5D="+url.QueryEscape(email)+"&user%5Bpassword%5D="+url.QueryEscape(password)+"&commit=Log+in")))
	if err != nil {
		utils.Log.Fatal(err)
	}

	req2.Header.Set("User-Agent", USER_AGENT)
	req2.Header.Set("Cookie", "_crowdcontrol_session_key="+crowdControlSession)
	resp2, err := client.Do(req2)
	if err != nil {
		panic(err)
	}
	defer resp2.Body.Close()

	sessionToken := ""
	for _, cookie := range resp2.Header["Set-Cookie"] {
		if strings.HasPrefix(cookie, "_crowdcontrol_session_key") {
			sessionToken = strings.TrimPrefix(cookie, "_crowdcontrol_session_key=")
			break
		}
	}

	if resp2.StatusCode != 302 {
		utils.Log.Fatal("Login failed", resp2.StatusCode)
	}

	return sessionToken
}

func GetProgramHandles(sessionToken string, bbpOnly bool, pvtOnly bool) []string {
	totalPages := 0
	pageIndex := 1

	listEndpointURL := "https://bugcrowd.com/programs.json?"
	if pvtOnly {
		listEndpointURL = listEndpointURL + "accepted_invite[]=true&"
	}
	if bbpOnly {
		listEndpointURL = listEndpointURL + "vdp[]=false&"
	}
	listEndpointURL = listEndpointURL + "hidden[]=false&sort[]=invited-desc&sort[]=promoted-desc&page[]="
	paths := []string{}

	for {
		var res *whttp.WHTTPRes
		var err error

		client := &http.Client{}

		for {
			res, err = whttp.SendHTTPRequest(
				&whttp.WHTTPReq{
					Method: "GET",
					URL:    listEndpointURL + strconv.Itoa(pageIndex),
					Headers: []whttp.WHTTPHeader{
						{Name: "Cookie", Value: "_crowdcontrol_session_key=" + sessionToken},
						{Name: "User-Agent", Value: USER_AGENT},
					},
				}, client)

			if err != nil {
				utils.Log.Fatal(err)
			}

			// Rate limiting retry
			if res.StatusCode != 429 {
				break
			} else {
				utils.Log.Warn("Hit rate limiting (429), retrying...")
				time.Sleep(RATE_LIMIT_SLEEP_SECONDS * time.Second)
			}
		}

		if totalPages == 0 {
			totalPages = int(gjson.Get(string(res.BodyString), "meta.totalPages").Int())
		}

		chunkData := gjson.Get(string(res.BodyString), "programs.#.program_url")
		for i := 0; i < len(chunkData.Array()); i++ {
			paths = append(paths, chunkData.Array()[i].Str)
		}

		pageIndex++

		if pageIndex > totalPages {
			break
		}

	}

	return paths
}

func GetProgramScope(handle string, categories string, token string) (pData scope.ProgramData) {
	r, err := regexp.Compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]")
	if err != nil {
		utils.Log.Fatal("Could not create regex pattern for handle ", handle)
	}
	pData.Url = "https://bugcrowd.com" + handle

	var res, res2 *whttp.WHTTPRes

	client := &http.Client{}

	for {
		res, err = whttp.SendHTTPRequest(
			&whttp.WHTTPReq{
				Method: "GET",
				URL:    pData.Url + "/target_groups",
				Headers: []whttp.WHTTPHeader{
					{Name: "Cookie", Value: "_crowdcontrol_session_key=" + token},
					{Name: "User-Agent", Value: USER_AGENT},
					{Name: "Accept", Value: "*/*"},
				},
			}, client)

		if err != nil {
			utils.Log.Fatal(err)
		}

		// Rate limiting retry
		if res.StatusCode != 429 {
			break
		} else {
			utils.Log.Warn("Hit rate limiting (429), retrying...")
			time.Sleep(RATE_LIMIT_SLEEP_SECONDS * time.Second)
		}
	}

	// Times @arcwhite broke our code: #3 and counting :D

	//noScopeTable := true
	for _, scopeTableURL := range gjson.Get(string(res.BodyString), "groups.#(in_scope==true)#.targets_url").Array() {

		// Send HTTP request for each table

		for {
			res2, err = whttp.SendHTTPRequest(
				&whttp.WHTTPReq{
					Method: "GET",
					URL:    "https://bugcrowd.com" + scopeTableURL.String(),
					Headers: []whttp.WHTTPHeader{
						{Name: "Cookie", Value: "_crowdcontrol_session_key=" + token},
						{Name: "User-Agent", Value: USER_AGENT},
						{Name: "Accept", Value: "*/*"},
					},
				}, client)

			if err != nil {
				utils.Log.Fatal(err)
			}

			// Rate limiting retry
			if res2.StatusCode != 429 {
				break
			} else {
				utils.Log.Warn("Hit rate limiting (429), retrying...")
				time.Sleep(RATE_LIMIT_SLEEP_SECONDS * time.Second)
			}
		}

		pData.Url = strings.TrimSuffix(handle, "/") + "_bc"

		var program Program

		err = json.Unmarshal([]byte(res.BodyString), &program)

		if err != nil {
			utils.Log.Fatal("Could not parse program for handle  ", handle, " with status ", res2.StatusCode)
		}

		targets := make(map[string]struct{})
		for _, target := range program.Targets {
			catMatches := categories == "all"
			for _, cat := range GetCategories(categories) {
				if cat == target.Category {
					catMatches = true
					break
				}
			}

			if catMatches {
				for _, match := range r.FindAllString(strings.ToLower(target.Name), -1) {
					_, ok := targets[match]
					if !ok {
						pData.InScope = append(pData.InScope, scope.ScopeElement{Target: match, Description: target.Description, Category: target.Category})
						targets[match] = struct{}{}
					}
				}
				for _, match := range r.FindAllString(strings.ToLower(target.Description), -1) {
					_, ok := targets[match]
					if !ok {
						pData.InScope = append(pData.InScope, scope.ScopeElement{Target: match, Description: target.Description, Category: target.Category})
						targets[match] = struct{}{}
					}
				}
				for _, match := range r.FindAllString(strings.ToLower(target.URI), -1) {
					_, ok := targets[match]
					if !ok {
						pData.InScope = append(pData.InScope, scope.ScopeElement{Target: match, Description: target.Description, Category: target.Category})
						targets[match] = struct{}{}
					}
				}
			}
		}
	}

	/*
		if noScopeTable {
			pData.InScope = append(pData.InScope, scope.ScopeElement{Target: "NO_IN_SCOPE_TABLE", Description: "", Category: ""})
		}
	*/

	return pData
}

func GetCategories(input string) []string {
	categories := map[string][]string{
		"url":      {"website"},
		"api":      {"api"},
		"mobile":   {"android", "ios"},
		"android":  {"android"},
		"apple":    {"ios"},
		"other":    {"other"},
		"hardware": {"hardware"},
		"allinfra": {"website", "api", "other"},
	}

	selectedCategory, ok := categories[strings.ToLower(input)]
	if !ok {
		utils.Log.Fatal("Invalid category")
	}
	return selectedCategory
}

func GetAllProgramsScope(token string, bbpOnly bool, pvtOnly bool, categories string, concurrency int) (programs []scope.ProgramData) {
	programHandles := GetProgramHandles(token, bbpOnly, pvtOnly)

	handles := make(chan string, concurrency)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			for {
				handle := <-handles

				if handle == "" {
					break
				}

				programs = append(programs, GetProgramScope(handle, categories, token))
			}
			processGroup.Done()
		}()
	}

	for _, handle := range programHandles {
		handles <- handle
	}

	close(handles)
	processGroup.Wait()
	return programs
}

// PrintAllScope prints to stdout all scope elements of all targets
func PrintAllScope(token string, bbpOnly bool, pvtOnly bool, categories string, outputFlags string, delimiter string, concurrency int) {
	programs := GetAllProgramsScope(token, bbpOnly, pvtOnly, categories, concurrency)
	for _, pData := range programs {
		scope.PrintProgramScope(pData, outputFlags, delimiter)
	}
}

/*
// ListPrograms prints a list of available programs
func ListPrograms(token string, bbpOnly bool, pvtOnly bool) {
	programPaths := GetProgramPagePaths(token, bbpOnly, pvtOnly)
	for _, path := range programPaths {
		fmt.Println("https://bugcrowd.com" + path)
	}
}*/
