package passkeys

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func hasColumn(t *testing.T, db *sql.DB, tableName, columnName string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + tableName + ")")
	if err != nil {
		t.Fatalf("failed to query table info for %s: %v", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid          int
			name         string
			colType      string
			notNull      int
			defaultValue sql.NullString
			pk           int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("failed to scan table info row: %v", err)
		}
		if name == columnName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("failed during table info iteration for %s: %v", tableName, err)
	}
	return false
}

// TestMigrateSchema_UpgradeExistingDB verifies that a database created under the previous
// schema (which lacked the 'roles' column) is cleanly upgraded without data loss.
func TestMigrateSchema_UpgradeExistingDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Create the legacy schema (the previous users table without 'roles')
	_, err = db.ExecContext(ctx, `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		userid BLOB,
		display_name TEXT,
		invitation_token TEXT,
		token_expiry DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		cred_type TEXT NOT NULL, 
		cred_id TEXT UNIQUE NOT NULL, 
		public_data BLOB NOT NULL,     
		sign_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE
	);
	`)
	if err != nil {
		t.Fatalf("failed to create legacy schema: %v", err)
	}

	// 2. Insert dummy user with legacy schema
	_, err = db.ExecContext(ctx, `INSERT INTO users (email, display_name) VALUES (?, ?)`, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("failed to insert legacy user: %v", err)
	}

	// Verify 'roles' column does NOT exist yet
	if hasColumn(t, db, "users", "roles") {
		t.Fatalf("expected 'roles' column to not exist initially in legacy schema")
	}

	// 3. Run MigrateSchema
	if err := MigrateSchema(ctx, db); err != nil {
		t.Fatalf("MigrateSchema failed on legacy db: %v", err)
	}

	// 4. Verify 'roles' column exists now
	if !hasColumn(t, db, "users", "roles") {
		t.Fatalf("expected 'roles' column to exist after migration")
	}

	// 5. Verify existing user data is intact
	var (
		email       string
		displayName string
		roles       sql.NullString
	)
	err = db.QueryRowContext(ctx, `SELECT email, display_name, roles FROM users WHERE email = ?`, "alice@example.com").
		Scan(&email, &displayName, &roles)
	if err != nil {
		t.Fatalf("failed to query migrated user: %v", err)
	}

	if email != "alice@example.com" || displayName != "Alice" {
		t.Errorf("expected email 'alice@example.com' and display_name 'Alice', got email %q, display_name %q", email, displayName)
	}
	if !roles.Valid || roles.String != "[]" {
		t.Errorf("expected roles '[]' for existing user with null roles, got %q", roles.String)
	}

	// 6. Test updating roles for the migrated user
	validPowers := `[{"type":"domain","domain":"goauth","function":"admin","action":["*"]}]`
	_, err = db.ExecContext(ctx, `UPDATE users SET roles = ? WHERE email = ?`, validPowers, "alice@example.com")
	if err != nil {
		t.Fatalf("failed to update roles on migrated user: %v", err)
	}

	err = db.QueryRowContext(ctx, `SELECT roles FROM users WHERE email = ?`, "alice@example.com").Scan(&roles)
	if err != nil || !roles.Valid || roles.String != validPowers {
		t.Errorf("expected roles %q, got %v (err: %v)", validPowers, roles, err)
	}
}

// TestMigrateSchema_DefaultRolesForNullOrEmpty verifies that MigrateSchema defaults null or empty roles to '[]'.
func TestMigrateSchema_DefaultRolesForNullOrEmpty(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Create a legacy table without NOT NULL / CHECK constraints to simulate existing unmigrated data
	_, err = db.ExecContext(ctx, `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			display_name TEXT,
			roles TEXT
		);
	`)
	if err != nil {
		t.Fatalf("failed to create test users table: %v", err)
	}

	validExistingPowers := `[{"type":"domain","domain":"goauth","function":"editor","action":["read"]}]`

	// Insert test users with NULL, empty, and non-empty valid JSON roles
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (email, display_name, roles) VALUES
		('null_roles@example.com', 'Null Roles', NULL),
		('empty_roles@example.com', 'Empty Roles', ''),
		('existing_roles@example.com', 'Existing Roles', ?);
	`, validExistingPowers)
	if err != nil {
		t.Fatalf("failed to insert test users: %v", err)
	}

	// Run migration to upgrade schema and set defaults
	if err := MigrateSchema(ctx, db); err != nil {
		t.Fatalf("MigrateSchema failed: %v", err)
	}

	tests := []struct {
		email         string
		expectedRoles string
	}{
		{"null_roles@example.com", "[]"},
		{"empty_roles@example.com", "[]"},
		{"existing_roles@example.com", validExistingPowers},
	}

	for _, tc := range tests {
		var roles sql.NullString
		err := db.QueryRowContext(ctx, `SELECT roles FROM users WHERE email = ?`, tc.email).Scan(&roles)
		if err != nil {
			t.Errorf("failed to query roles for %s: %v", tc.email, err)
			continue
		}
		if !roles.Valid || roles.String != tc.expectedRoles {
			t.Errorf("for user %s: expected roles %q, got %q", tc.email, tc.expectedRoles, roles.String)
		}
	}
}

// TestMigrateSchema_FreshDB verifies that a fresh database gets the 'roles' column.
func TestMigrateSchema_FreshDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	if err := MigrateSchema(ctx, db); err != nil {
		t.Fatalf("MigrateSchema failed on fresh db: %v", err)
	}

	if !hasColumn(t, db, "users", "roles") {
		t.Fatalf("expected 'roles' column to exist in fresh db")
	}
}

// TestMigrateSchema_Idempotency verifies that running MigrateSchema multiple times does not error.
func TestMigrateSchema_Idempotency(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := MigrateSchema(ctx, db); err != nil {
			t.Fatalf("iteration %d: MigrateSchema failed: %v", i, err)
		}
	}

	if !hasColumn(t, db, "users", "roles") {
		t.Fatalf("expected 'roles' column to exist after repeated migrations")
	}
}

// TestNewPasskeys_WithExistingDB verifies NewPasskeys automatically migrates existing DB.
func TestNewPasskeys_WithExistingDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	// Create legacy users table
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		userid BLOB
	);`)
	if err != nil {
		t.Fatalf("failed to create legacy users table: %v", err)
	}

	pk, err := NewPasskeys(Config{
		DB: db,
	})
	if err != nil {
		t.Fatalf("NewPasskeys failed: %v", err)
	}
	defer pk.Close()

	if !hasColumn(t, db, "users", "roles") {
		t.Fatalf("expected NewPasskeys to automatically migrate and add 'roles' column")
	}
}
