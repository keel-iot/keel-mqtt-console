package auth

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword("correct horse battery staple", hash) {
		t.Fatal("expected password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("wrong password verified")
	}
}

func TestValidateRole(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "acl_admin", "admin"} {
		if !ValidateRole(role) {
			t.Fatalf("role %q should be valid", role)
		}
	}
	if ValidateRole("root") {
		t.Fatal("unexpected role accepted")
	}
}
