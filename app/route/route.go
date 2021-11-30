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

	h := handlers.NewUserHandler(db)

	e.POST("/signup", h.Signup)
	e.POST("/login", h.Login)
	e.GET("/logout", handlers.Logout)
}
