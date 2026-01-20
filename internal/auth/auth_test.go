package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr bool
		errType error
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			want:    "test-key-123",
			wantErr: false,
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: true,
			errType: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": []string{""}},
			want:    "",
			wantErr: true,
			errType: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header - missing api key value",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: true,
		},
		{
			name:    "malformed header - wrong scheme",
			headers: http.Header{"Authorization": []string{"Bearer test-key"}},
			want:    "",
			wantErr: true,
		},
		{
			name:    "malformed header - too many parts",
			headers: http.Header{"Authorization": []string{"ApiKey test-key extra"}},
			want:    "test-key",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
