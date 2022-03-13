# Gin Middleware for HCaptcha Integration

[![Run Tests](https://github.com/kleash/gin-hcaptcha/actions/workflows/go.yml/badge.svg)](https://github.com/kleash/gin-hcaptcha/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/kleash/gin-hcaptcha/branch/main/graph/badge.svg)](https://codecov.io/gh/kleash/gin-hcaptcha)
[![Go Report Card](https://goreportcard.com/badge/github.com/kleash/gin-hcaptcha)](https://goreportcard.com/report/github.com/kleash/gin-hcaptcha)
[![GoDoc](https://godoc.org/github.com/kleash/gin-hcaptcha?status.svg)](https://godoc.org/github.com/kleash/gin-hcaptcha)

Gin middleware/handler to enable HCaptcha support.

## Usage

### Start using it

Download and install it:

```sh
go get github.com/kleash/gin-hcaptcha
```

Import it in your code:

```go
import "github.com/kleash/gin-hcaptcha"
```

### Start with default config

```go
package main

import (
  . "github.com/kleash/gin-hcaptcha"
  "github.com/gin-gonic/gin"
)

func main() {
  router := gin.Default()
  hCaptchaMw, err := NewWithDefaults("0x0000000000000000000000000000000000000000")
  if err != nil {
	panic(err.Error())
  }

  router.POST("/", hCaptchaMw.MiddlewareFunc(), func(c *gin.Context) {
	  c.String(200, "good")
  })
}
```

### Available Optional configs
| **Config**                 |                    **Description**                     | **Default Value**                                          |
|:---------------------------|:------------------------------------------------------:|:-----------------------------------------------------------|
| **SiteKey**                |             Set this to validate site key              |                                                            |
| **EnableUserIpValidation** |                 Validate User Ip Also                  | false                                                      |
| **ErrResp**                |             Custom error response function             | {"message": "invalid captcha} </br> HTTP Status Code = 403 |
| **HttpClient**             | Custom http client to communicate with HCaptcha Server | `http.Client{Timeout: 10s}`                                |
| **GetCaptchaResponse**     |        Custom function to get captcha response         | Value of `h-captcha-response` from form value              |
| **HCaptchaUrl**            |                  HCaptcha server url                   | https://hcaptcha.com/siteverify                            |

