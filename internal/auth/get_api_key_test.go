package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)

	if !reflect.DeepEqual(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer 12345")

	_, err := GetAPIKey(headers)

	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key != "my-secret-key" {
		t.Fatalf("expected 'my-secret-key', got %s", key)
	}
}
