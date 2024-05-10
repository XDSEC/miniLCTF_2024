package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"

	_ "github.com/lib/pq"
)

func genCaptcha() (string, string) {
	charset := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	captcha := make([]byte, 4)
	token := make([]byte, 16)
	for i := 0; i < 4; i++ {
		captcha[i] = charset[rand.Intn(len(charset))]
	}
	for i := 0; i < 16; i++ {
		token[i] = charset[rand.Intn(len(charset))]
	}

	return string(captcha), string(token)
}

func queryCaptcha(key, token string) bool {
	query := fmt.Sprintf("SELECT COUNT(*) FROM captcha_view WHERE key = '%s' AND token = '%s';", key, token)
	f := newQuery()
	if err := f.DbCall(query); err != nil {
		log.Printf("failed to execute query: %v\n", err)
		return false
	}
	return f.Success && f.Result.(int64) > 0
}

func queryUser(username, password string) (bool, bool) {
	userQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE username = '%s';", username)
	userQueryResult := &FastQuery{}
	if err := userQueryResult.DbCall(userQuery); err != nil {
		log.Printf("failed to execute query: %v\n", err)
		return false, false
	}
	userExists := userQueryResult.Success && userQueryResult.Result.(int64) > 0

	passwordQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE username = '%s' AND password = '%s';", username, password)
	passwordQueryResult := &FastQuery{}
	if err := passwordQueryResult.DbCall(passwordQuery); err != nil {
		log.Printf("failed to execute query: %v\n", err)
		return false, false
	}
	correctPassword := passwordQueryResult.Success && passwordQueryResult.Result.(int64) > 0

	return userExists, correctPassword
}

type FastQuery struct {
	Success bool
	Result  any
}

var db *sql.DB

func newQuery() *FastQuery {
	return &FastQuery{false, ""}
}

func connectDb() {
	var err error
	db, err = sql.Open("postgres", "postgres://postgres:Compl3xP@ssw0rD@/postgres?host=/var/run/postgresql/&sslmode=disable")
	//db, err = sql.Open("postgres", "postgres://postgres:password@127.0.0.1:5544/postgres?sslmode=disable")
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
}

func (f *FastQuery) DbCall(query string) interface{} {
	if db == nil {
		connectDb()
	}
	if err := db.Ping(); err != nil {
		fmt.Println("Database connection lost, reconnecting...")
		if err := db.Close(); err != nil {
			log.Printf("failed to close database connection: %v\n", err)
		}
		connectDb()
	}

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("failed to execute query: %v\n", err)
		return err
	}
	defer rows.Close()

	f.Success = true

	for rows.Next() {
		var result interface{}
		if err := rows.Scan(&result); err != nil {
			log.Printf("failed to scan row: %v\n", err)
			return err
		}
		f.Result = result
		return nil
	}
	return nil
}
