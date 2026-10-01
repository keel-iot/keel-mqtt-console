package httpapi

import "testing"

func TestHandlerBuildsWithoutRouteConflicts(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Handler panicked while registering routes: %v", recovered)
		}
	}()

	if Handler := (&Server{}).Handler(); Handler == nil {
		t.Fatal("expected a non-nil handler")
	}
}
