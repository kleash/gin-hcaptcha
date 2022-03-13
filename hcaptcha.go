package hcaptcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// GinHCaptchaMiddleware provides a HCaptcha middleware for a Gin based application.
// All the available options can be found in this struct.
type GinHCaptchaMiddleware struct {
	//HCaptcha secret to verify captcha responses, get from dashboard: https://dashboard.hcaptcha.com/settings
	Secret string

	//Optional. The site key you expect to see, disabled by default
	SiteKey string

	//Optional. Validate the user's IP address, enabled by default
	EnableUserIpValidation bool

	//Optional. Custom error response function, defaulted to defaultErrResponse
	ErrResp func(c *gin.Context)

	//Optional. Custom function to get captcha response, defaulted to defaultGetCaptchaResponse
	GetCaptchaResponse func(c *gin.Context) string

	//Optional. HTTPClient to call site verify of HCaptcha
	HttpClient netClient

	//Optional. HCaptcha URL for site verify
	HCaptchaUrl string
}

//HTTP Client to call site verify of HCaptcha
type netClient interface {
	PostForm(url string, formValues url.Values) (resp *http.Response, err error)
}

// NewWithDefaults returns a GinHCaptchaMiddleware with default configurations
func NewWithDefaults(secret string) (*GinHCaptchaMiddleware, error) {
	hcmw := &GinHCaptchaMiddleware{
		Secret: secret,
	}
	return hcmw, New(hcmw)
}

// New validates the provided configuration and defaults missing parameters
func New(m *GinHCaptchaMiddleware) error {
	if m.Secret == "" {
		return errors.New("mandatory parameter: secret key is missing")
	}
	if m.ErrResp == nil {
		m.ErrResp = defaultErrResponse()
	}
	if m.GetCaptchaResponse == nil {
		m.GetCaptchaResponse = defaultGetCaptchaResponse()
	}
	if m.HttpClient == nil {
		m.HttpClient = defaultHttpClient()
	}
	if m.HCaptchaUrl == "" {
		m.HCaptchaUrl = defaultHCaptchaUrl
	}
	return nil
}

// MiddlewareFunc is used in Gin Router as the middleware function of GinHCaptchaMiddleware
func (mw *GinHCaptchaMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if mw.validateCaptcha(c) {
			c.Next()
		} else {
			mw.ErrResp(c)
			c.Abort()
		}
	}
}

type hCHAPTCHAResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname,omitempty"`
	Credit      bool      `json:"credit,omitempty"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
	Score       float32   `json:"score,omitempty"`
	ScoreReason string    `json:"score_reason,omitempty"`
}

var (
	// defaultErrorStatusCode returns 403 when captcha verification fails
	defaultErrorStatusCode = http.StatusForbidden

	// defaultErrorMessage returns default error message  when captcha verification fails
	defaultErrorMessage = "invalid captcha"

	// defaultHTTPTimeout is used as default timeout while invoking recaptcha site verify
	defaultHTTPTimeout = 10 * time.Second

	//defaultHCaptchaUrl indicates HCaptcha Url for site verify
	defaultHCaptchaUrl = "https://hcaptcha.com/siteverify"
)

func defaultErrResponse() func(c *gin.Context) {
	return func(c *gin.Context) {
		c.JSON(defaultErrorStatusCode, gin.H{
			"message": defaultErrorMessage,
		})
	}
}

func defaultGetCaptchaResponse() func(c *gin.Context) string {
	return func(c *gin.Context) string {
		//Default key from HCaptcha developer guide: https://docs.hcaptcha.com/#add-the-hcaptcha-widget-to-your-webpage
		return c.PostForm("h-captcha-response")
	}
}

func defaultHttpClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
	}
}

func (mw *GinHCaptchaMiddleware) validateCaptcha(c *gin.Context) bool {
	var formValues = url.Values{"secret": {mw.Secret}, "response": {mw.GetCaptchaResponse(c)}}
	if mw.EnableUserIpValidation {
		formValues.Set("remoteip", c.ClientIP())
	}
	if mw.SiteKey != "" {
		formValues.Set("sitekey", mw.SiteKey)
	}
	res, err := mw.HttpClient.PostForm(mw.HCaptchaUrl, formValues)
	if err != nil {
		fmt.Printf("Error in siteverify. Response: %+v, Error: %+v", res, err)
		return false
	}
	defer res.Body.Close()
	resultBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error in siteverify. Cannot read response body, Response: %+v, Error: %+v", res, err)
		return false
	}
	var result hCHAPTCHAResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		fmt.Printf("Error in siteverify. Cannot read parse response body, Response: %+v, Error: %+v", res, err)
		return false
	}
	if !result.Success {
		return false
	}
	return true
}
