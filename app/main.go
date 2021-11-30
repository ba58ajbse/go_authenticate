package main

import (
	"go_todo/database"
	"go_todo/model"
	"go_todo/route"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type jwtCustomClaims struct {
	model.User
	jwt.StandardClaims
}

var signingKey = []byte("secret")

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func user(c echo.Context) error {
	cookie, err := c.Cookie("token")
	if err != nil {
		return echo.ErrCookieNotFound
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})

	if err != nil || !token.Valid {
		return echo.ErrUnauthorized
	}

	claims := token.Claims.(*jwtCustomClaims)
	name := claims.Name

	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {
	e := echo.New()

	// middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://www.thunderclient.io", "http://localhost:3000"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
	}))

	// db
	database.Init()
	db := database.GetDB()
	defer database.CloseDB()

	// routing
	route.NewRouter(e, db)

	e.GET("/", accessible)

	r := e.Group("/user")
	r.GET("", user)

	// start
	e.Logger.Fatal(e.Start(":8080"))
}
