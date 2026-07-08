package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatUserRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles []userRole
		want  string
	}{
		{"none", nil, "-"},
		{"empty slice", []userRole{}, "-"},
		{"single", []userRole{{Name: "admin"}}, "admin"},
		{"multiple joined", []userRole{{Name: "admin"}, {Name: "audit"}}, "admin,audit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, formatUserRoles(tt.roles))
		})
	}
}
