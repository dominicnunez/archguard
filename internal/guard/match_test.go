package guard

import "testing"

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{name: "segment wildcard", pattern: "internal/*/adapters/postgres", value: "internal/token/adapters/postgres", want: true},
		{name: "segment wildcard does not cross slash", pattern: "internal/*/postgres", value: "internal/token/adapters/postgres", want: false},
		{name: "double wildcard", pattern: "internal/**/postgres", value: "internal/token/adapters/postgres", want: true},
		{name: "question", pattern: "internal/toke?", value: "internal/token", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wildcardMatch(tt.pattern, tt.value); got != tt.want {
				t.Fatalf("wildcardMatch(%q, %q) = %v; want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}
