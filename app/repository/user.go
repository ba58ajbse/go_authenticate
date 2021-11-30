package repository

import (
	"database/sql"
	"go_todo/model"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Signup(db sql.DB, u model.User) (model.User, error)
	Login(db sql.DB, u model.User) (model.User, error)
}

type userRepository struct{}

func NewUserRepository() UserRepository {
	return &userRepository{}
}

func (r *userRepository) Signup(db sql.DB, u model.User) (model.User, error) {
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

	return u, nil
}

func (r *userRepository) Login(db sql.DB, u model.User) (model.User, error) {
	password := u.Password
	err := db.QueryRow("SELECT * FROM users WHERE email = ?", u.Email).
		Scan(&u.Id, &u.Name, &u.Email, &u.Password, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return u, err
	}

	bcrypt_err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if bcrypt_err != nil {
		return u, bcrypt_err
	}

	return u, err
}
