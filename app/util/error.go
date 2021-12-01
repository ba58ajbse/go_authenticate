package util

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type APIError struct {
	Status  int    `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func JSONError(c echo.Context, status int, code int) {
	msg := http.StatusText(status)
	apiErr := &APIError{
		Status:  status,
		Code:    code,
		Message: msg,
	}

	c.JSON(status, apiErr)
}

func CustomErrorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	msg := http.StatusText(code)

	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
	}

	apiErr := &APIError{
		Code:    code,
		Message: msg,
	}

	if !c.Response().Committed {
		c.JSON(code, apiErr)
	}

	c.Logger().Error(err)
}
