// Package security provides security utilities for safe command execution and input validation.
package security

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// CommandAllowlist defines the allowed commands and their permitted arguments.
// This implements a whitelist approach for maximum security.
type CommandAllowlist struct {
	allowedCommands map[string]CommandPolicy
}

// CommandPolicy defines security policy for a specific command.
type CommandPolicy struct {
	// ExecutablePath is the full path to the allowed executable.
	ExecutablePath string

	// AllowedArgs are regex patterns for permitted arguments.
	AllowedArgs []string

	// MaxExecutionTime is the maximum allowed execution time.
	MaxExecutionTime time.Duration

	// AllowEnvironment indicates if environment variables are allowed.
	AllowEnvironment bool

	// RequiredUser specifies the required user (if any).
	RequiredUser string
}

// SecureExecutor provides safe command execution with enterprise security controls.
type SecureExecutor struct {
	allowlist          CommandAllowlist
	defaultTimeout     time.Duration
	maxOutputSize      int64
	disallowedPatterns []*regexp.Regexp
}

// ExecutionResult contains the result of a secure command execution.
type ExecutionResult struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"error,omitempty"`
}

// NewSecureExecutor creates a new secure command executor with enterprise defaults.
func NewSecureExecutor() *SecureExecutor {
	executor := &SecureExecutor{
		allowlist:      NewDefaultAllowlist(),
		defaultTimeout: 30 * time.Second,
		maxOutputSize:  1024 * 1024, // 1MB max output
	}

	// Compile disallowed patterns for injection detection
	executor.compileDisallowedPatterns()

	return executor
}

// NewDefaultAllowlist creates a secure allowlist for common monitoring commands.
func NewDefaultAllowlist() CommandAllowlist {
	allowlist := CommandAllowlist{
		allowedCommands: make(map[string]CommandPolicy),
	}

	// Docker commands
	allowlist.allowedCommands["docker"] = CommandPolicy{
		ExecutablePath:   "/usr/bin/docker",
		AllowedArgs:      []string{"^ps$", "^stats$", "^--no-stream$", "^--format$", "^table$"},
		MaxExecutionTime: 10 * time.Second,
		AllowEnvironment: false,
	}

	// System commands for monitoring
	allowlist.allowedCommands["ps"] = CommandPolicy{
		ExecutablePath:   "/bin/ps",
		AllowedArgs:      []string{"^-aux$", "^-ef$", "^-o$", "^pid,comm,cpu,mem$"},
		MaxExecutionTime: 5 * time.Second,
		AllowEnvironment: false,
	}

	// Network monitoring
	allowlist.allowedCommands["ss"] = CommandPolicy{
		ExecutablePath:   "/usr/bin/ss",
		AllowedArgs:      []string{"^-tuln$", "^-s$"},
		MaxExecutionTime: 5 * time.Second,
		AllowEnvironment: false,
	}

	// Package management (for update checking)
	allowlist.allowedCommands["apt"] = CommandPolicy{
		ExecutablePath:   "/usr/bin/apt",
		AllowedArgs:      []string{"^list$", "^--upgradable$"},
		MaxExecutionTime: 15 * time.Second,
		AllowEnvironment: false,
	}

	allowlist.allowedCommands["yum"] = CommandPolicy{
		ExecutablePath:   "/usr/bin/yum",
		AllowedArgs:      []string{"^check-update$", "^--quiet$"},
		MaxExecutionTime: 15 * time.Second,
		AllowEnvironment: false,
	}

	return allowlist
}

// compileDisallowedPatterns compiles regex patterns for injection detection.
func (se *SecureExecutor) compileDisallowedPatterns() {
	patterns := []string{
		`[;&|]`,       // Command injection separators
		`\$\(.*\)`,    // Command substitution
		"`.*`",        // Backtick command substitution
		`\.\./`,       // Path traversal
		`\x00`,        // Null bytes
		`<\s*script`,  // Script injection
		`javascript:`, // JavaScript injection
		`data:`,       // Data URL injection
	}

	se.disallowedPatterns = make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		se.disallowedPatterns[i] = regexp.MustCompile(pattern)
	}
}

// ExecuteSecure executes a command with comprehensive security validation.
func (se *SecureExecutor) ExecuteSecure(ctx context.Context, command string, args ...string) (ExecutionResult, error) {
	result := ExecutionResult{}
	start := time.Now()

	// Validate command is allowed
	policy, err := se.validateCommand(command, args)
	if err != nil {
		result.Error = fmt.Errorf("command validation failed: %w", err)
		return result, result.Error
	}

	// Check for injection patterns
	if err := se.detectInjection(command, args); err != nil {
		result.Error = fmt.Errorf("injection attempt detected: %w", err)
		return result, result.Error
	}

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, policy.MaxExecutionTime)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, policy.ExecutablePath, args...)

	// Configure command security
	se.configureCommandSecurity(cmd, policy)

	// Execute with output limits
	stdout, stderr, err := se.executeWithLimits(cmd)

	result.Duration = time.Since(start)
	result.Stdout = stdout
	result.Stderr = stderr
	result.Error = err

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	return result, nil
}

// validateCommand checks if a command and its arguments are allowed.
func (se *SecureExecutor) validateCommand(command string, args []string) (CommandPolicy, error) {
	policy, exists := se.allowlist.allowedCommands[command]
	if !exists {
		return CommandPolicy{}, fmt.Errorf("command '%s' is not in allowlist", command)
	}

	// Validate each argument against allowed patterns
	for _, arg := range args {
		allowed := false
		for _, pattern := range policy.AllowedArgs {
			matched, err := regexp.MatchString(pattern, arg)
			if err != nil {
				return CommandPolicy{}, fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
			}
			if matched {
				allowed = true
				break
			}
		}

		if !allowed {
			return CommandPolicy{}, fmt.Errorf("argument '%s' is not allowed for command '%s'", arg, command)
		}
	}

	return policy, nil
}

// detectInjection scans for potential injection attempts.
func (se *SecureExecutor) detectInjection(command string, args []string) error {
	allInput := append([]string{command}, args...)

	for _, input := range allInput {
		for _, pattern := range se.disallowedPatterns {
			if pattern.MatchString(input) {
				return fmt.Errorf("potentially malicious pattern detected in: %s", input)
			}
		}
	}

	return nil
}

// configureCommandSecurity applies security configuration to the command.
func (se *SecureExecutor) configureCommandSecurity(cmd *exec.Cmd, policy CommandPolicy) {
	// Clear environment if not allowed
	if !policy.AllowEnvironment {
		cmd.Env = []string{}
	}

	// Set working directory to safe location
	cmd.Dir = "/tmp"

	// Additional security measures would go here:
	// - Set process limits
	// - Configure user/group if specified
	// - Set up cgroups for resource limiting
}

// executeWithLimits executes the command with output size limits.
func (se *SecureExecutor) executeWithLimits(cmd *exec.Cmd) (string, string, error) {
	// For production, implement proper output streaming with size limits
	// This is a simplified version for demonstration

	output, err := cmd.CombinedOutput()

	// Check output size
	if int64(len(output)) > se.maxOutputSize {
		return "", "", fmt.Errorf("command output exceeded maximum size limit")
	}

	return string(output), "", err
}

// SanitizeInput provides enterprise-grade input sanitization.
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove potential command injection characters
	dangerousChars := []string{";", "&", "|", "`", "$", "(", ")", "<", ">"}
	for _, char := range dangerousChars {
		input = strings.ReplaceAll(input, char, "")
	}

	// Limit length
	maxLength := 1024
	if len(input) > maxLength {
		input = input[:maxLength]
	}

	return strings.TrimSpace(input)
}

// ValidateHostname ensures hostname follows security standards.
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	if len(hostname) > 255 {
		return fmt.Errorf("hostname too long: %d > 255", len(hostname))
	}

	// Hostname must contain only alphanumeric characters, hyphens, and dots
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("hostname contains invalid characters")
	}

	// Additional checks for security
	if strings.Contains(hostname, "..") {
		return fmt.Errorf("hostname contains invalid sequence '..'")
	}

	return nil
}

// ValidateMetricName ensures metric names follow security standards.
func ValidateMetricName(name string) error {
	if name == "" {
		return fmt.Errorf("metric name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("metric name too long: %d > 100", len(name))
	}

	// Metric names must follow Prometheus conventions
	metricRegex := regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	if !metricRegex.MatchString(name) {
		return fmt.Errorf("metric name format is invalid")
	}

	return nil
}

// SecureString provides a secure string type that prevents accidental logging.
type SecureString struct {
	value string
}

// NewSecureString creates a new secure string.
func NewSecureString(value string) SecureString {
	return SecureString{value: value}
}

// String implements the Stringer interface but returns masked value.
func (s SecureString) String() string {
	if len(s.value) <= 8 {
		return "***"
	}
	return s.value[:4] + "***"
}

// Value returns the actual value (use with caution).
func (s SecureString) Value() string {
	return s.value
}

// IsEmpty returns true if the secure string is empty.
func (s SecureString) IsEmpty() bool {
	return s.value == ""
}
