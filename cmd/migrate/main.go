package main

//
// A small CLI utility for running database migrations
//

import (
	"errors"
	"flag"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/rshelekhov/golib/config"
	appConfig "github.com/rshelekhov/sso/internal/config"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var migrationsPath string

	flag.StringVar(&migrationsPath, "migrations-path", "./migrations", "path to migrations")
	flag.Parse()

	cfg := config.MustLoad[appConfig.ServerSettings](
		config.WithSkipFlags(true),
	)

	if migrationsPath == "" {
		// I'm fine with panic for now, as it's an auxiliary utility.
		panic("migrations-path is required")
	}

	// Create a migrate object by passing the credentials to our database
	m, err := migrate.New(
		"file://"+migrationsPath,
		cfg.Storage.Postgres.ConnURL,
	)
	if err != nil {
		panic(err)
	}

	// Migrate to the latest version
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("no migrations to apply")

			return
		}

		panic(err)
	}
}
