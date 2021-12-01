package repository

import (
	"database/sql"
	"go_todo/model"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	FindByEmail(db sql.DB, u model.User) (model.User, error)
	Create(db sql.DB, u model.User) (model.User, error)
}

type userRepository struct{}

func NewUserRepository() UserRepository {
	return &userRepository{}
}

func (r *userRepository) FindByEmail(db sql.DB, u model.User) (model.User, error) {
	err := db.QueryRow("SELECT * FROM users WHERE email = ?", u.Email).
		Scan(&u.Id, &u.Name, &u.Email, &u.Password, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return u, err
	}

	return u, err
}

func (r *userRepository) Create(db sql.DB, u model.User) (model.User, error) {
	tx, err := db.Begin()
	if err != nil {
		return u, err
	}
	defer tx.Rollback()

	stmt, err := db.Prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)")
	if err != nil {
		return u, err
	}
	defer stmt.Close()

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(u.Password), 10)

	res, err := stmt.Exec(u.Name, u.Email, hashedPass)
	if err != nil {
		return u, err
	}

	lastId, err := res.LastInsertId()
	if err != nil {
		return u, err
	}

	u.Id = int(lastId)
	u.Password = string(hashedPass)

	return u, nil
}
