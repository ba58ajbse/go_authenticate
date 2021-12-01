package route

import (
	"database/sql"
	"go_todo/handlers"
	"net/http"

	"github.com/labstack/echo/v4"
)

func NewRouter(e *echo.Echo, db *sql.DB) {
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "Hello, World!")
	})

	auth := handlers.NewAuthHandler(db)

	e.POST("/signup", auth.Signup)
	e.POST("/login", auth.Login)
	e.GET("/logout", auth.Logout)
}
