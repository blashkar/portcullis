//go:build ollama

// The guard model against a real Ollama. Run with:
//
//	go test -tags ollama -run TestEvaluate -v ./internal/inject
//
// PORTCULLIS_GUARD_MODEL picks the model (default gemma3:4b) and
// OLLAMA_HOST the server.
package inject

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/ollama"
	"github.com/blashkar/portcullis/internal/scan"
)

type score struct{ tp, fp, tn, fn int }

func (s *score) add(want, got bool) {
	switch {
	case want && got:
		s.tp++
	case want:
		s.fn++
	case got:
		s.fp++
	default:
		s.tn++
	}
}

func (s score) String() string {
	return fmt.Sprintf("%2d/%-2d caught, %d/%d false alarms", s.tp, s.tp+s.fn, s.fp, s.fp+s.tn)
}

func TestEvaluate(t *testing.T) {
	client, err := ollama.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	model := cmp.Or(os.Getenv("PORTCULLIS_GUARD_MODEL"), DefaultModel)
	g := NewGuard(client, GuardOptions{Model: model, Timeout: 2 * time.Minute, Concurrency: 1})
	ctx := context.Background()
	// Load the model first so the first sample's latency isn't load time.
	if _, err := g.Check(ctx, "warm-up text for the guard model"); err != nil {
		t.Fatalf("guard model %s: %v", model, err)
	}

	sets := []string{"corpus", "holdout"}
	if only := os.Getenv("PORTCULLIS_EVAL_SET"); only != "" {
		sets = []string{only}
	}
	for _, set := range sets {
		samples := loadSet(t, "testdata/"+set+".json")
		var patterns, guard, both score
		var latencies []time.Duration
		for _, s := range samples {
			p := MaxSeverity(Heuristics(s.Text)) == scan.High
			start := time.Now()
			v, err := g.Check(ctx, s.Text)
			latencies = append(latencies, time.Since(start))
			if err != nil {
				t.Fatalf("%s: %v", s.Name, err)
			}
			patterns.add(s.Injection, p)
			guard.add(s.Injection, v.Injection)
			both.add(s.Injection, p || v.Injection)
			if s.Injection != (p || v.Injection) || s.Injection != v.Injection {
				t.Logf("  %-9s %-28s want %-5v patterns %-5v guard %-5v (%s)", set, s.Name, s.Injection, p, v.Injection, v.Reason)
			}
		}
		slices.Sort(latencies)
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		t.Logf("%s (%d samples), model %s:", set, len(samples), model)
		t.Logf("  patterns only: %v", patterns)
		t.Logf("  guard only:    %v", guard)
		t.Logf("  combined:      %v", both)
		t.Logf("  guard latency: median %v, max %v, mean %v",
			latencies[len(latencies)/2].Round(time.Millisecond), latencies[len(latencies)-1].Round(time.Millisecond),
			(total / time.Duration(len(latencies))).Round(time.Millisecond))
	}
}
