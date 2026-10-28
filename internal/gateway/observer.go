package gateway

import "github.com/blashkar/portcullis/internal/audit"

// Observer is told about each event as it happens, with details the audit
// log keeps only as text.
type Observer interface {
	Observe(e audit.Event, d Details)
}

// Details are what the gateway did to a message, beyond its audit event.
type Details struct {
	// Redacted counts the secrets redacted from it, by kind.
	Redacted map[string]int
	// Injection is true when the injection checks judged it a prompt
	// injection; Suspicious when they noticed something but didn't.
	Injection, Suspicious bool
	// Approval is how a call that needed a person's approval ended:
	// approved, denied, expired, cancelled or refused; "" if it didn't need one.
	Approval string
	// Withheld is true when the result was withheld as an injection.
	Withheld bool
}

func (n *callNote) details() Details {
	var d Details
	if len(n.redacted) > 0 {
		d.Redacted = map[string]int{}
		for kind, secrets := range n.redacted {
			d.Redacted[kind] = len(secrets)
		}
	}
	d.Injection = n.injected
	d.Suspicious = n.injection != "" && !n.injected
	d.Withheld = n.withheld
	if n.approval != 0 {
		d.Approval = n.approval.String()
	}
	return d
}
