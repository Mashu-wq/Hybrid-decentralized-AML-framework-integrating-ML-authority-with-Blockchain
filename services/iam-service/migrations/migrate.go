package migrations

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"

	"path/filepath"
	"sort"
	"strings"

	"iam-service/config"

	_ "github.com/lib/pq"
)

type Migration struct {
	Version int
	Name    string
	Content string
}

func RunMigrations(cfg *config.Config) error {
	// Connect to database
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create migrations table if not exists
	if err := createMigrationsTable(db); err != nil {
		return err
	}

	// Get applied migrations
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	// Load migration files
	migrations, err := loadMigrationFiles()
	if err != nil {
		return err
	}

	// Apply pending migrations
	for _, migration := range migrations {
		if applied[migration.Version] {
			log.Printf("Migration %d_%s already applied, skipping", migration.Version, migration.Name)
			continue
		}

		log.Printf("Applying migration %d_%s", migration.Version, migration.Name)

		// Execute migration in transaction
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		// Split by semicolon for individual statements
		statements := strings.Split(migration.Content, ";")
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}

			// Add semicolon back
			stmt = stmt + ";"

			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to execute migration %d_%s: %w", migration.Version, migration.Name, err)
			}
		}

		// Record migration as applied
		if _, err := tx.Exec(
			"INSERT INTO iam_schema.migrations (version, name) VALUES ($1, $2)",
			migration.Version, migration.Name,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration: %w", err)
		}

		log.Printf("Migration %d_%s applied successfully", migration.Version, migration.Name)
	}

	log.Println("All migrations applied successfully")
	return nil
}

func createMigrationsTable(db *sql.DB) error {
	// First, ensure schema exists
	_, err := db.Exec(`
		CREATE SCHEMA IF NOT EXISTS iam_schema;
		
		CREATE TABLE IF NOT EXISTS iam_schema.migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`)
	return err
}

func getAppliedMigrations(db *sql.DB) (map[int]bool, error) {
	applied := make(map[int]bool)

	// Check if migrations table exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'iam_schema' 
			AND table_name = 'migrations'
		)
	`).Scan(&exists)

	if err != nil || !exists {
		return applied, nil
	}

	rows, err := db.Query("SELECT version FROM iam_schema.migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, nil
}

func loadMigrationFiles() ([]Migration, error) {
	var migrations []Migration

	files, err := ioutil.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}

		filename := file.Name()
		// Parse version and name from filename (e.g., "001_create_schema.sql")
		var version int
		var name string

		parts := strings.SplitN(strings.TrimSuffix(filename, ".sql"), "_", 2)
		if len(parts) != 2 {
			continue
		}

		_, err := fmt.Sscanf(parts[0], "%d", &version)
		if err != nil {
			continue
		}
		name = parts[1]

		// Read file content
		content, err := ioutil.ReadFile(filepath.Join("migrations", filename))
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			Content: string(content),
		})
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}