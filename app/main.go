package main

import (
	"go_todo/database"
	"go_todo/model"
	"go_todo/route"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

type jwtCustomClaims struct {
	model.User
	jwt.StandardClaims
}

var signingKey = []byte("secret")

var config = middleware.JWTConfig{
	Claims:     &jwtCustomClaims{},
	SigningKey: signingKey,
}

func signup(c echo.Context) error {
	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	user := new(model.User)
	if err := c.Bind(user); err != nil {
		return echo.ErrInternalServerError
	}

	db := database.GetDB()
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := db.Prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	res, err := stmt.Exec(name, email, hashedPass)
	if err != nil {
		return err
	}

	lastId, err := res.LastInsertId()
	if err != nil {
		return err
	}

	user.Id = int(lastId)

	return c.JSON(http.StatusOK, user)
}

// func login(c echo.Context) error {
// 	username := c.FormValue("username")
// 	password := c.FormValue("password")

// 	if username != "jon" || password != "shhh!" {
// 		return echo.ErrUnauthorized
// 	}

// 	claims := &jwtCustomClaims{
// 		"Jon Snow",
// 		true,
// 		jwt.StandardClaims{
// 			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
// 			IssuedAt:  time.Now().Unix(),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

// 	t, err := token.SignedString(signingKey)
// 	if err != nil {
// 		return err
// 	}

// 	cookie := new(http.Cookie)
// 	cookie.Name = "token"
// 	cookie.Value = t
// 	cookie.Expires = time.Now().Add(24 * time.Hour)
// 	c.SetCookie(cookie)

// 	return c.JSON(http.StatusOK, echo.Map{
// 		"token": t,
// 	})
// }
func login(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	u := model.User{}

	db := database.GetDB()
	defer db.Close()

	err := db.QueryRow("SELECT * FROM users WHERE email = ?", email).
		Scan(&u.Id, &u.Name, &u.Email, &u.Password, &u.CreatedAt, &u.UpdatedAt)
	bcrypt_err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))

	if bcrypt_err != nil {
		return echo.ErrUnauthorized
	}

	claims := &jwtCustomClaims{
		u,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString(signingKey)
	if err != nil {
		return err
	}

	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = t
	cookie.Expires = time.Now().Add(24 * time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{
		"user": u,
	})
}

func logout(c echo.Context) error {
	cookie, err := c.Cookie("token")

	if err != nil {
		return echo.ErrCookieNotFound
	}

	cookie.Name = "token"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, "Successful logout.")
}

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

	e.POST("/login", login)
	e.GET("/", accessible)

	e.POST("/signup", signup)
	e.GET("/logout", logout)

	r := e.Group("/user")
	r.GET("", user)
	// start
	e.Logger.Fatal(e.Start(":8080"))
}
