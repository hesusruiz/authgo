package passkeys

import (
	"testing"
)

func TestCreateInvitationConflict(t *testing.T) {
	pk, err := NewPasskeys(Config{
		DBSourceName: ":memory:",
		PathPrefix:   "/passkeys",
	})
	if err != nil {
		t.Fatalf("failed to initialize Passkeys: %v", err)
	}
	defer pk.Close()

	email := "user@example.com"

	// First invitation
	powers1 := []OnePower{
		{
			Type:     "domain",
			Domain:   "goauth",
			Function: "admin",
			Action:   []string{"*"},
		},
	}
	token1, err := pk.InviteUserPowers(email, powers1)
	if err != nil {
		t.Fatalf("first InviteUser failed: %v", err)
	}

	var storedToken1 string
	err = pk.db.QueryRow("SELECT invitation_token FROM users WHERE email = ?", email).Scan(&storedToken1)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if storedToken1 != token1 {
		t.Fatalf("expected stored token %q, got %q", token1, storedToken1)
	}

	// Second invitation (conflict on email)
	powers2 := []OnePower{
		{
			Type:     "domain",
			Domain:   "goauth",
			Function: "editor",
			Action:   []string{"read", "write"},
		},
	}
	token2, err := pk.InviteUserPowers(email, powers2)
	if err != nil {
		t.Fatalf("second InviteUser failed: %v", err)
	}

	var storedToken2 string
	var roles2 string
	err = pk.db.QueryRow("SELECT invitation_token, roles FROM users WHERE email = ?", email).Scan(&storedToken2, &roles2)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	t.Logf("storedToken1: %s, storedToken2: %s, roles2: %s", storedToken1, storedToken2, roles2)
	if storedToken2 != token2 {
		t.Fatalf("expected stored token to be updated to %q, but got %q", token2, storedToken2)
	}

	u, err := pk.GetInvitation(token2)
	if err != nil {
		t.Fatalf("GetInvitation failed: %v", err)
	}
	if len(u.Roles()) == 0 || u.Roles()[0].Function != "editor" {
		t.Fatalf("expected user role function 'editor', got %+v", u.Roles())
	}
}

func TestInviteUser(t *testing.T) {
	pk, err := NewPasskeys(Config{
		DBSourceName: ":memory:",
		PathPrefix:   "/passkeys",
	})
	if err != nil {
		t.Fatalf("failed to initialize Passkeys: %v", err)
	}
	defer pk.Close()

	for i := 0; i < 20; i++ {
		token, err := pk.InviteUserPowers("test@example.com", []OnePower{
			{
				Type:     "domain",
				Domain:   "goauth",
				Function: "user",
				Action:   []string{"read"},
			},
		})
		if err != nil {
			t.Fatalf("InviteUser failed: %v", err)
		}
		if len(token) != 16 {
			t.Fatalf("expected token length 16, got %d (token: %q)", len(token), token)
		}
	}
}
