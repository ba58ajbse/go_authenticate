package database

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

var (
	db  *sql.DB
	err error
)

func Init() {
	if err := godotenv.Load("../.env"); err != nil {
		log.Fatalln("Fatal load env: ", err)
	}

	db_user := os.Getenv("DB_USER")
	db_pass := os.Getenv("DB_PASS")
	db_name := os.Getenv("DB_NAME")
	db_host := os.Getenv("DB_HOST")
	db_port := os.Getenv("DB_PORT")

	dsn := db_user + ":" + db_pass + "@tcp(" + db_host + ":" + db_port + ")/" + db_name

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalln("Fatal db open: ", err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	err = db.Ping()
	if err != nil {
		log.Fatalln("Fatal db ping: ", err)
	}
}

func GetDB() *sql.DB {
	return db
}

func CloseDB() {
	db.Close()
}
