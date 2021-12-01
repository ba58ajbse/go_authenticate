package util

import (
	"go_todo/model"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type jwtCustomClaims struct {
	model.User
	jwt.StandardClaims
}

func ReadCookie(c echo.Context, name string) (*jwtCustomClaims, error) {
	cookie, err := c.Cookie(name)
	if err != nil {
		JSONError(c, http.StatusUnauthorized, 401)
		return nil, err
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil || !token.Valid {
		JSONError(c, http.StatusUnauthorized, 401)
		return nil, err
	}

	claims := token.Claims.(*jwtCustomClaims)

	return claims, nil
}

func WriteCookie(c echo.Context, n string, v string) {
	cookie := &http.Cookie{
		Name:    n,
		Value:   v,
		Expires: time.Now().Add(24 * time.Hour),
	}

	c.SetCookie(cookie)
}

func ClearCookie(c echo.Context, n string, cookie *http.Cookie) {
	cookie.Name = n
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)

	c.SetCookie(cookie)
}
