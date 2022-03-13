package hcaptcha

import (
	"bytes"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHCaptchaMw(t *testing.T) {
	//Initialize Router
	router := setupRouter(t)
	w := httptest.NewRecorder()

	//HCaptcha valid response
	data := url.Values{}
	data.Set("h-captcha-response", "10000000-aaaa-bbbb-cccc-000000000001")

	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "good", w.Body.String())
}

func TestHCaptchaMw_InvalidResponse(t *testing.T) {
	//Initialize Router
	router := setupRouter(t)
	w := httptest.NewRecorder()

	//HCaptcha valid response
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	_ = mw.WriteField("h-captcha-response", "10000000-aaaa-ccccc-cccc-000000000001")
	_ = mw.Close()

	req, _ := http.NewRequest("POST", "/", buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	router.ServeHTTP(w, req)

	assert.Equal(t, defaultErrorStatusCode, w.Code)
	assert.Equal(t, fmt.Sprintf("{\"message\":\"%s\"}", defaultErrorMessage), w.Body.String())
}

func setupRouter(t *testing.T) *gin.Engine {
	router := gin.Default()
	hCaptchaMw, err := NewWithDefaults("0x0000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err.Error())
	}

	router.POST("/", hCaptchaMw.MiddlewareFunc(), func(c *gin.Context) {
		c.String(200, "good")
	})
	return router
}

func TestNewWithDefaults(t *testing.T) {
	type args struct {
		secret string
	}
	tests := []struct {
		name    string
		args    args
		want    *GinHCaptchaMiddleware
		wantErr bool
	}{
		{
			name:    "Returns valid Client",
			args:    args{secret: "test secret"},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Returns error if no secret passed",
			args:    args{secret: ""},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWithDefaults(tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Default() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		m *GinHCaptchaMiddleware
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Returns valid Client",
			args: args{m: &GinHCaptchaMiddleware{
				Secret:                 "2qews",
				SiteKey:                "",
				EnableUserIpValidation: false,
				ErrResp:                nil,
				GetCaptchaResponse:     nil,
				HttpClient:             nil,
				HCaptchaUrl:            "",
			}},
			wantErr: false,
		},
		{
			name: "Returns error if no secret passed",
			args: args{m: &GinHCaptchaMiddleware{
				Secret:                 "",
				SiteKey:                "",
				EnableUserIpValidation: false,
				ErrResp:                nil,
				GetCaptchaResponse:     nil,
				HttpClient:             nil,
				HCaptchaUrl:            "",
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New(tt.args.m); (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGinHCaptchaMiddleware_validateCaptcha(t *testing.T) {
	type fields struct {
		Secret                 string
		SiteKey                string
		EnableUserIpValidation bool
		ErrResp                func(c *gin.Context)
		GetCaptchaResponse     func(c *gin.Context) string
		HttpClient             netClient
		HCaptchaUrl            string
	}
	type args struct {
		c *gin.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Validate correct captcha response",
			fields: fields{
				Secret:                 "0x0000000000000000000000000000000000000000",
				EnableUserIpValidation: false,
				ErrResp:                defaultErrResponse(),
				GetCaptchaResponse:     defaultGetCaptchaResponse(),
				HttpClient:             defaultHttpClient(),
				HCaptchaUrl:            defaultHCaptchaUrl,
			},
			args: args{
				c: mockGinContextWithValidHCaptchaResponse(),
			},
			want: true,
		},
		{
			name: "Validate correct captcha response with site key",
			fields: fields{
				Secret:                 "0x0000000000000000000000000000000000000000",
				SiteKey:                "10000000-ffff-ffff-ffff-000000000001",
				EnableUserIpValidation: false,
				ErrResp:                defaultErrResponse(),
				GetCaptchaResponse:     defaultGetCaptchaResponse(),
				HttpClient:             defaultHttpClient(),
				HCaptchaUrl:            defaultHCaptchaUrl,
			},
			args: args{
				c: mockGinContextWithValidHCaptchaResponse(),
			},
			want: true,
		},
		{
			name: "Validate invalid captcha response",
			fields: fields{
				Secret:                 "0x0000000000000000000000000000000000000000",
				EnableUserIpValidation: false,
				ErrResp:                defaultErrResponse(),
				GetCaptchaResponse:     defaultGetCaptchaResponse(),
				HttpClient:             defaultHttpClient(),
				HCaptchaUrl:            defaultHCaptchaUrl,
			},
			args: args{
				c: mockGinContextWithInvalidHCaptchaResponse(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &GinHCaptchaMiddleware{
				Secret:                 tt.fields.Secret,
				SiteKey:                tt.fields.SiteKey,
				EnableUserIpValidation: tt.fields.EnableUserIpValidation,
				ErrResp:                tt.fields.ErrResp,
				GetCaptchaResponse:     tt.fields.GetCaptchaResponse,
				HttpClient:             tt.fields.HttpClient,
				HCaptchaUrl:            tt.fields.HCaptchaUrl,
			}
			_ = New(mw)
			if got := mw.validateCaptcha(tt.args.c); got != tt.want {
				t.Errorf("validateCaptcha() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mockGinContextWithHCaptchaResponse(userHCaptchaResponse string) *gin.Context {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	_ = mw.WriteField("h-captcha-response", userHCaptchaResponse)
	_ = mw.Close()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("POST", "/", buf)
	c.Request.Header.Set("Content-Type", mw.FormDataContentType())
	return c
}

func mockGinContextWithInvalidHCaptchaResponse() *gin.Context {
	return mockGinContextWithHCaptchaResponse("randominvalidresponse")
}

func mockGinContextWithValidHCaptchaResponse() *gin.Context {
	return mockGinContextWithHCaptchaResponse("10000000-aaaa-bbbb-cccc-000000000001")
}
