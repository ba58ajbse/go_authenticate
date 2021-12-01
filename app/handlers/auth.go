package handlers

import (
	"database/sql"
	"fmt"
	"go_todo/model"
	"go_todo/repository"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler interface {
	Signup(c echo.Context) error
	Login(c echo.Context) error
	Logout(c echo.Context) error
}

type authHandler struct {
	db       sql.DB
	authRepo repository.UserRepository
}

type jwtCustomClaims struct {
	model.User
	jwt.StandardClaims
}

func NewAuthHandler(db *sql.DB) AuthHandler {
	return &authHandler{
		db:       *db,
		authRepo: repository.NewUserRepository(),
	}
}

func (h *authHandler) Signup(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	fmt.Println(u)
	_, err := h.authRepo.FindByEmail(h.db, *u)
	switch {
	case err == sql.ErrNoRows:
		user, err := h.authRepo.Create(h.db, *u)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}

		return c.JSON(http.StatusOK, user)
	case err != nil:
		return c.JSON(http.StatusInternalServerError, err)
	default:
		return c.JSON(http.StatusConflict, "既に使用されたメールアドレスです。")
	}
}

func (h *authHandler) Login(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	password := u.Password
	user, err := h.authRepo.FindByEmail(h.db, *u)
	if err != nil {
		return c.JSON(http.StatusNotFound, "登録されたユーザーが見つかりません。")
	}

	bcrypt_err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if bcrypt_err != nil {
		return c.JSON(http.StatusNotFound, "登録されたユーザーが見つかりません。")
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

	cookie := &http.Cookie{
		Name:    "token",
		Value:   t,
		Expires: time.Now().Add(24 * time.Hour),
	}
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, "ログイン成功")
}

func (h *authHandler) Logout(c echo.Context) error {
	cookie, err := c.Cookie("token")
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	cookie.Name = "token"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, "ログアウト成功")
}
