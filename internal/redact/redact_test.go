package redact

import (
	"regexp"
	"strings"
	"testing"
)

// The fake secrets are built at run time, so the source has nothing that
// looks like a real key to secret scanners.
var (
	awsKey    = "AKIA" + strings.Repeat("Q7", 8)
	awsSecret = strings.Repeat("wJalrXUtnFEMIK7MDENGbPxRfiCY", 2)[:40]
	ghToken   = "ghp_" + strings.Repeat("a1B2", 9)
	ghPAT     = "github_pat_" + strings.Repeat("11ABCDEFG0", 7)
	antKey    = "sk-ant-api03-" + strings.Repeat("x9", 20)
	slack     = "xoxb-" + "1234567890-abcdefghij"
	stripe    = "sk_" + "live_" + strings.Repeat("4eC39HqLyjWD", 2)
	google    = "AIza" + strings.Repeat("SyD-9", 7)
	jwt       = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	pemKey    = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQyNTUxOQAAACD\n-----END OPENSSH " + "PRIVATE KEY-----"
)

func TestRedacts(t *testing.T) {
	tests := []struct {
		name, in, want string
		kind           string
	}{
		{"aws access key", "key id " + awsKey + " in use", "key id [REDACTED:aws_access_key] in use", "aws_access_key"},
		{"aws secret", "aws_secret_access_key = " + awsSecret, "aws_secret_access_key = [REDACTED:aws_secret_key]", "aws_secret_key"},
		{"github token", "token: " + ghToken, "token: [REDACTED:github_token]", "github_token"},
		{"github pat", ghPAT, "[REDACTED:github_token]", "github_token"},
		{"anthropic", "ANTHROPIC_API_KEY=" + antKey, "ANTHROPIC_API_KEY=[REDACTED:anthropic_key]", "anthropic_key"},
		{"slack", slack, "[REDACTED:slack_token]", "slack_token"},
		{"stripe", stripe, "[REDACTED:stripe_key]", "stripe_key"},
		{"google", "key=" + google + "&q=1", "key=[REDACTED:google_api_key]&q=1", "google_api_key"},
		{"jwt", "Authorization: Bearer " + jwt, "Authorization: Bearer [REDACTED:jwt]", "jwt"},
		{"private key", "before\n" + pemKey + "\nafter", "before\n[REDACTED:private_key]\nafter", "private_key"},
		{"truncated private key", "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow", "[REDACTED:private_key]", "private_key"},
		{"url password", "postgres://app:s3cr3t-pw@db.internal:5432/x", "postgres://app:[REDACTED:url_password]@db.internal:5432/x", "url_password"},
		{"assignment", `DB_PASSWORD="correct-horse-battery"`, `DB_PASSWORD="[REDACTED:secret_assignment]"`, "secret_assignment"},
		{"json field", `{"client_secret": "abc123def456"}`, `{"client_secret": "[REDACTED:secret_assignment]"}`, "secret_assignment"},
	}
	r := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, counts := r.String(tt.in)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if counts.N(tt.kind) != 1 || len(counts) != 1 {
				t.Errorf("counts = %v, want one %s", counts, tt.kind)
			}
		})
	}
}

func TestLeavesOrdinaryTextAlone(t *testing.T) {
	r := New()
	for _, s := range []string{
		"The password is required and must be at least 8 characters.",
		"commit 6c7ff1a160994505f47f376016a033b87376a77c",
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"https://example.com/path?page=2",
		"token_count: 123456789",
		"# Demo project\n\nA made-up project for trying portcullis.",
		"secret = short",
	} {
		if got, counts := r.String(s); got != s || counts != nil {
			t.Errorf("%q became %q (%v)", s, got, counts)
		}
	}
}

func TestNoDoubleRedaction(t *testing.T) {
	// The AWS rule takes the value first; the generic assignment rule then
	// sees a marker, not a secret.
	got, counts := New().String("aws_secret_access_key=" + awsSecret + "\napi_key=" + awsKey)
	if got != "aws_secret_access_key=[REDACTED:aws_secret_key]\napi_key=[REDACTED:aws_access_key]" {
		t.Errorf("got %q", got)
	}
	if counts.String() != "aws_access_key, aws_secret_key" {
		t.Errorf("counts = %v", counts)
	}
}

func TestExtraRules(t *testing.T) {
	r := New(Rule{Name: "internal_token", Pattern: regexp.MustCompile(`itk_[a-z0-9]{8}`)})
	got, counts := r.String("itk_abcd1234 and itk_efgh5678")
	if got != "[REDACTED:internal_token] and [REDACTED:internal_token]" || counts.String() != "internal_token×2" {
		t.Errorf("got %q, %v", got, counts)
	}
}

func TestDistinctSecretsCount(t *testing.T) {
	r := New()
	counts := Counts{}
	for _, s := range []string{"a " + ghToken, "b " + ghToken, "c " + strings.Replace(ghToken, "a1", "z9", 1)} {
		_, c := r.String(s)
		counts.Add(c)
	}
	if counts.String() != "github_token×2" {
		t.Errorf("counts = %v, want two distinct tokens", counts)
	}
}

func TestValue(t *testing.T) {
	v := map[string]any{"env": []any{"HOME=/root", "GH=" + ghToken}, "n": 3.0, "nested": map[string]any{"k": jwt}}
	counts := Counts{}
	New().Value(v, counts)
	if v["env"].([]any)[1] != "GH=[REDACTED:github_token]" || v["nested"].(map[string]any)["k"] != "[REDACTED:jwt]" || v["n"] != 3.0 {
		t.Errorf("value = %v", v)
	}
	if counts.String() != "github_token, jwt" {
		t.Errorf("counts = %v", counts)
	}
}

func TestNilRedactor(t *testing.T) {
	var r *Redactor
	if got, c := r.String(ghToken); got != ghToken || c != nil {
		t.Error("a nil Redactor changed its input")
	}
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{ghToken, pemKey, "password=" + awsSecret, "x://u:p@h", "[REDACTED:jwt]"} {
		f.Add(s)
	}
	r := New()
	f.Fuzz(func(t *testing.T, s string) {
		once, _ := r.String(s)
		// Redacting is idempotent: nothing in the output looks like a secret.
		if twice, c := r.String(once); twice != once || c != nil {
			t.Errorf("%q -> %q -> %q (%v)", s, once, twice, c)
		}
	})
}
