package fim

// Scope chooses how much of the platform's default ruleset is watched.
type Scope string

const (
	// ScopeCredentials watches the account, privilege, authentication and
	// persistence files only: a few dozen files, cheap to hash and to watch.
	// It is what an agent runs when netwarden.conf does not mention FIM.
	ScopeCredentials Scope = "credentials"
	// ScopeFull adds the system binary directories (and on OPNsense the whole
	// config.xml), which is what enable_fim: true has always meant. Hashing
	// the binaries is the sustained I/O that kept FIM opt-in.
	ScopeFull Scope = "full"
)

// WithScope selects the default ruleset; ScopeCredentials unless set.
func WithScope(s Scope) Option {
	return func(c *Collector) { c.scope = s }
}
