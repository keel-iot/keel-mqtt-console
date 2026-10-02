package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestHandlerServesBrandIcon(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/keel-icon-square.svg", nil)
	res := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected icon status 200, got %d", res.Code)
	}
	if got := res.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("expected SVG content type, got %q", got)
	}
	if !strings.Contains(res.Body.String(), "Keel icon") {
		t.Fatal("expected embedded Keel icon payload")
	}
}
