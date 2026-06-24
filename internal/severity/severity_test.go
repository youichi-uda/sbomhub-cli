package severity

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]Level{
		"":             LevelNone,
		"   ":          LevelNone,
		"unknown":      LevelNone,
		"low":          LevelLow,
		"LOW":          LevelLow,
		"medium":       LevelMedium,
		"high":         LevelHigh,
		"HIGH":         LevelHigh,
		"critical":     LevelCritical,
		"Critical":     LevelCritical,
		"kev":          LevelKEV,
		"KEV":          LevelKEV,
	}
	for in, want := range cases {
		if got := Parse(in); got != want {
			t.Errorf("Parse(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestShouldFail(t *testing.T) {
	type tc struct {
		name      string
		counts    Counts
		threshold Level
		want      bool
	}
	cases := []tc{
		{"no threshold returns false even with criticals", Counts{Critical: 5}, LevelNone, false},
		{"clean below low threshold", Counts{}, LevelLow, false},
		{"low at low threshold", Counts{Low: 1}, LevelLow, true},
		{"high at high threshold", Counts{High: 1}, LevelHigh, true},
		{"medium at high threshold does not fire", Counts{Medium: 5}, LevelHigh, false},
		{"critical at high threshold fires (cascading)", Counts{Critical: 1}, LevelHigh, true},
		{"critical at critical threshold fires", Counts{Critical: 1}, LevelCritical, true},
		{"high at critical threshold does not fire", Counts{High: 5}, LevelCritical, false},
		{"kev presence fires kev threshold", Counts{KEV: 1}, LevelKEV, true},
		{"kev presence at critical threshold fires", Counts{KEV: 1}, LevelCritical, true},
		{"low at medium threshold does not fire", Counts{Low: 1}, LevelMedium, false},
		// Codex R2 regression: Unknown is reported but MUST NOT fail any
		// threshold. The justification (data-quality bucket, not CRA risk)
		// is documented on Counts.Unknown.
		{"unknown alone at low threshold does not fire", Counts{Unknown: 7}, LevelLow, false},
		{"unknown alone at high threshold does not fire", Counts{Unknown: 7}, LevelHigh, false},
		{"unknown alone at critical threshold does not fire", Counts{Unknown: 7}, LevelCritical, false},
		{"unknown alone at kev threshold does not fire", Counts{Unknown: 7}, LevelKEV, false},
		{"unknown + critical still fires on critical via the critical bucket", Counts{Unknown: 7, Critical: 1}, LevelCritical, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldFail(tt.counts, tt.threshold); got != tt.want {
				t.Errorf("ShouldFail(%+v, %v) = %v, want %v", tt.counts, tt.threshold, got, tt.want)
			}
		})
	}
}
