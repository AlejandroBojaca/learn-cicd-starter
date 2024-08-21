package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API key",
			headers:     http.Header{"Authorization": {"ApiKey abc123"}},
			expectedKey: "abc123",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization header",
			headers:     http.Header{"Authorization": {"Bearer abc123"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Incomplete Authorization header",
			headers:     http.Header{"Authorization": {"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.expectedKey {
				t.Errorf("expected key %v, got %v", tt.expectedKey, apiKey)
			}
			if err != nil && tt.expectedErr != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			} else if err != nil && tt.expectedErr == nil {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil && tt.expectedErr != nil {
				t.Errorf("expected error %v, got no error", tt.expectedErr)
			}
		})
	}
}
