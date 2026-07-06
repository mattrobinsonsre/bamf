package bridge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShortID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short does not panic", "abc", "abc"},
		{"exactly 16", "0123456789abcdef", "0123456789abcdef"},
		{"long is truncated", "0123456789abcdef0123", "0123456789abcdef..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shortID(tt.in))
		})
	}
}
