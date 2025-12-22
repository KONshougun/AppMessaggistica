package databaseConnection

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

const (
	DBUser     = "server:"
	DBPassword = "2hvhZMSrmfIIdE4D"
	DBHost     = "localhost"
	DBPort     = ":3306"
	DBName     = "appMessaggistica"
)

func StartConnection() (*sql.DB, error) {

	dsn := DBUser + DBPassword + "@tcp(" + DBHost + DBPort + ")/" + DBName

	// Apriamo la connessione
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Test connessione
	err = db.Ping()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return db, nil
}

/*
func ConnectToDatabase(query string) *sql.Rows {
	dsn := DBUser + DBPassword + "@tcp(" + DBHost + DBPort + ")/" + DBName

	// Apriamo la connessione
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Test connessione
	err = db.Ping()
	if err != nil {
		log.Fatal("Errore di connessione:", err)
	}

	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Iteriamo sui risultati
	for rows.Next() {
		var id int
		var nome string
		if err := rows.Scan(&id, &nome); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ID: %d - Nome: %s\n", id, nome)
	}

	return rows
}
*/
