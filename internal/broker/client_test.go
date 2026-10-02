package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoPreservesQueryForPaginatedClientRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/live/clients" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("page"); got != "2" {
			t.Errorf("page query = %q, want 2", got)
		}
		if got := r.URL.Query().Get("page_size"); got != "50" {
			t.Errorf("page_size query = %q, want 50", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(server.URL)
	resp, err := client.Do(context.Background(), http.MethodGet, "/api/live/clients?page=2&page_size=50", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
