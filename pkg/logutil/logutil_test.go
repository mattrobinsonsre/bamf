package logutil

import "testing"

func TestSafe(t *testing.T) {
	cases := map[string]string{
		"plain":              "plain",
		"with\nnewline":      "withnewline",
		"carriage\rreturn":   "carriagereturn",
		"forged\r\nAUDIT ok": "forgedAUDIT ok",
		"":                   "",
	}
	for in, want := range cases {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}
