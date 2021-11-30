package handlers

import (
	"database/sql"
	"go_todo/model"
	"go_todo/repository"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type UserHandler interface {
	Signup(c echo.Context) error
	Login(c echo.Context) error
}

type userHandler struct {
	db       sql.DB
	userRepo repository.UserRepository
}

type jwtCustomClaims struct {
	model.User
	jwt.StandardClaims
}

func NewUserHandler(db *sql.DB) UserHandler {
	return &userHandler{
		db:       *db,
		userRepo: repository.NewUserRepository(),
	}
}

func (h *userHandler) Signup(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	user, err := h.userRepo.Signup(h.db, *u)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	return c.JSON(http.StatusOK, user)
}

func (h *userHandler) Login(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	user, err := h.userRepo.Login(h.db, *u)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, err)
	}

	claims := &jwtCustomClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return c.JSON(http.StatusUnauthorized, err)
	}

	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = t
	cookie.Expires = time.Now().Add(24 * time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, u)
}

func Logout(c echo.Context) error {
	cookie, err := c.Cookie("token")
	if err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	cookie.Name = "token"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusNoContent, "Successful logout.")
}
