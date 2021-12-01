package handlers

import (
	"database/sql"
	"go_todo/model"
	"go_todo/repository"
	"go_todo/util"
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

var JSONError = util.JSONError

func NewAuthHandler(db *sql.DB) AuthHandler {
	return &authHandler{
		db:       *db,
		authRepo: repository.NewUserRepository(),
	}
}

func (h *authHandler) Signup(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		JSONError(c, http.StatusBadRequest, 400)
		return err
	}

	// 登録済みのユーザーであるか検証してから登録処理を行う
	_, err := h.authRepo.FindByEmail(h.db, *u)
	switch {
	case err == sql.ErrNoRows:
		user, err := h.authRepo.Create(h.db, *u)
		if err != nil {
			JSONError(c, http.StatusInternalServerError, 500)
			return err
		}
		return c.JSON(http.StatusOK, user)
	case err != nil:
		JSONError(c, http.StatusInternalServerError, 500)
		return err
	default:
		JSONError(c, http.StatusConflict, 409)
		return err
	}
}

func (h *authHandler) Login(c echo.Context) error {
	u := new(model.User)
	if err := c.Bind(u); err != nil {
		JSONError(c, http.StatusBadRequest, 400)
		return err
	}

	password := u.Password
	user, err := h.authRepo.FindByEmail(h.db, *u)
	if err != nil {
		JSONError(c, http.StatusUnauthorized, 401)
		return err
	}

	bcrypt_err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if bcrypt_err != nil {
		JSONError(c, http.StatusUnauthorized, 401)
		return err
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
		JSONError(c, http.StatusUnauthorized, 401)
		return err
	}

	util.WriteCookie(c, "token", t)

	return c.JSON(http.StatusOK, "ログイン成功")
}

func (h *authHandler) Logout(c echo.Context) error {
	cookie, err := c.Cookie("token")
	if err != nil {
		JSONError(c, http.StatusUnauthorized, 401)
		return err
	}

	util.ClearCookie(c, "token", cookie)

	return c.JSON(http.StatusOK, "ログアウト成功")
}
