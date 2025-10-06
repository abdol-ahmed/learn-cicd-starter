package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey1(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "no authorization header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - missing ApiKey prefix",
			headerValue: "Bearer somekey",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "malformed header - only ApiKey",
			headerValue: "ApiKey",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "malformed header - empty value after ApiKey",
			headerValue: "ApiKey ",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "valid header",
			headerValue: "ApiKey my-secret-key",
			wantKey:     "my-secret-key",
			wantErr:     nil,
		},
		// {
		// 	name:        "valid header with extra spaces",
		// 	headerValue: "ApiKey    another-key",
		// 	wantKey:     "",
		// 	wantErr:     errors.New("malformed authorization header"),
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}
			gotKey, gotErr := GetAPIKey(headers)
			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
			if (gotErr == nil) != (tt.wantErr == nil) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, gotErr)
			}
			if gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("expected error %q, got %q", tt.wantErr.Error(), gotErr.Error())
			}
		})
	}
}
