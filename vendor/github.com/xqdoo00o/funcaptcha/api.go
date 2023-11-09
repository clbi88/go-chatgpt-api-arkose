package funcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const arkPreURL = "https://tcr9i.chat.openai.com/fc/gt2/"

var initVer, initHex, arkURL, arkBx string
var arkCookies []*http.Cookie
var arkHeader http.Header
var arkBody url.Values
var (
	jar     = tls_client.NewCookieJar()
	options = []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(360),
		tls_client.WithClientProfile(profiles.Chrome_117),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}
	client *tls_client.HttpClient
	proxy  = os.Getenv("http_proxy")
)

type kvPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Expires string `json:"expires"`
}
type postBody struct {
	Params []kvPair `json:"params"`
}
type request struct {
	URL      string   `json:"url"`
	Headers  []kvPair `json:"headers,omitempty"`
	PostData postBody `json:"postData,omitempty"`
	Cookies  []cookie `json:"cookies,omitempty"`
}
type entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Request         request `json:"request"`
}
type logData struct {
	Entries []entry `json:"entries"`
}
type HARData struct {
	Log logData `json:"log"`
}

func readHAR() {
	file, err := os.ReadFile("chat.openai.com.har")
	if err != nil {
		return
	}
	var harFile HARData
	err = json.Unmarshal(file, &harFile)
	if err != nil {
		println("Error: not a HAR file!")
		return
	}
	var arkReq entry
	for _, v := range harFile.Log.Entries {
		if strings.HasPrefix(v.Request.URL, arkPreURL) {
			arkReq = v
			arkURL = v.Request.URL
			break
		}
	}
	if arkReq.StartedDateTime == "" {
		println("Error: no arkose request!")
		return
	}
	t, err := time.Parse(time.RFC3339, arkReq.StartedDateTime)
	if err != nil {
		panic(err)
	}
	bw := getBw(t.Unix())
	fallbackBw := getBw(t.Unix() - 21600)
	arkHeader = make(http.Header)
	for _, h := range arkReq.Request.Headers {
		// arkHeader except cookie & content-length
		if !strings.EqualFold(h.Name, "content-length") && !strings.EqualFold(h.Name, "cookie") && !strings.HasPrefix(h.Name, ":") {
			arkHeader.Set(h.Name, h.Value)
			if strings.EqualFold(h.Name, "user-agent") {
				bv = h.Value
			}
		}
	}
	arkCookies = []*http.Cookie{}
	for _, cookie := range arkReq.Request.Cookies {
		expire, _ := time.Parse(time.RFC3339, cookie.Expires)
		if expire.After(time.Now()) {
			arkCookies = append(arkCookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value, Expires: expire.UTC()})
		}
	}
	arkBody = make(url.Values)
	for _, p := range arkReq.Request.PostData.Params {
		// arkBody except bda & rnd
		if p.Name == "bda" {
			cipher, err := url.QueryUnescape(p.Value)
			if err != nil {
				panic(err)
			}
			arkBx = Decrypt(cipher, bv+bw, bv+fallbackBw)
		} else if p.Name != "rnd" {
			query, err := url.QueryUnescape(p.Value)
			if err != nil {
				panic(err)
			}
			arkBody.Set(p.Name, query)
		}
	}
	if arkBx != "" {
		println("success read HAR file")
	} else {
		println("failed to decrypt HAR file")
	}
}

//goland:noinspection GoUnhandledErrorResult
func init() {
	initVer = "1.5.4"
	initHex = "cd12da708fe6cbe6e068918c38de2ad9" // should be fixed associated with version.
	readHAR()
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	u, _ := url.Parse(arkPreURL)
	cli.GetCookieJar().SetCookies(u, arkCookies)
	client = &cli
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

//goland:noinspection GoUnusedExportedFunction
func SetTLSClient(cli *tls_client.HttpClient) {
	u, _ := url.Parse(arkPreURL)
	(*cli).GetCookieJar().SetCookies(u, arkCookies)
	client = cli
}

func GetOpenAIToken(puid string, proxy string) (string, error) {
	token, err := sendRequest("", puid, proxy)
	return token, err
}

func GetOpenAITokenWithBx(bx string, puid string, proxy string) (string, error) {
	token, err := sendRequest(getBdaWitBx(bx), puid, proxy)
	return token, err
}

//goland:noinspection SpellCheckingInspection,GoUnhandledErrorResult
func sendRequest(bda string, puid string, proxy string) (string, error) {
	if arkBx == "" || len(arkBody) == 0 || len(arkHeader) == 0 {
		return "", errors.New("a valid HAR file required")
	}
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
	if bda == "" {
		bda = getBDA()
	}
	arkBody.Set("bda", base64.StdEncoding.EncodeToString([]byte(bda)))
	arkBody.Set("rnd", strconv.FormatFloat(rand.Float64(), 'f', -1, 64))
	req, _ := http.NewRequest(http.MethodPost, arkURL, strings.NewReader(arkBody.Encode()))
	req.Header = arkHeader.Clone()
	if puid != "" {
		req.Header.Set("cookie", "_puid="+puid+";")
	}
	resp, err := (*client).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("status code " + resp.Status)
	}

	type arkoseResponse struct {
		Token string `json:"token"`
	}
	var arkose arkoseResponse
	err = json.NewDecoder(resp.Body).Decode(&arkose)
	if err != nil {
		return "", err
	}
	// Check if rid is empty
	if !strings.Contains(arkose.Token, "sup=1|rid=") {
		return arkose.Token, errors.New("captcha required")
	}

	return arkose.Token, nil
}

//goland:noinspection SpellCheckingInspection
func getBDA() string {
	bx := arkBx
	if bx == "" {
		bx = fmt.Sprintf(bx_template,
			getF(),
			getN(),
			getWh(),
			webglExtensions,
			getWebglExtensionsHash(),
			webglRenderer,
			webglVendor,
			webglVersion,
			webglShadingLanguageVersion,
			webglAliasedLineWidthRange,
			webglAliasedPointSizeRange,
			webglAntialiasing,
			webglBits,
			webglMaxParams,
			webglMaxViewportDims,
			webglUnmaskedVendor,
			webglUnmaskedRenderer,
			webglVsfParams,
			webglVsiParams,
			webglFsfParams,
			webglFsiParams,
			getWebglHashWebgl(),
			initVer,
			initHex,
			getFe(),
			getIfeHash(),
		)
	} else {
		re := regexp.MustCompile(`"key"\:"n","value"\:"\S*?"`)
		bx = re.ReplaceAllString(bx, `"key":"n","value":"`+getN()+`"`)
	}
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}

func getBt() int64 {
	return time.Now().UnixMicro() / 1000000
}

func getBw(bt int64) string {
	return strconv.FormatInt(bt-(bt%21600), 10)
}

func getBdaWitBx(bx string) string {
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}
