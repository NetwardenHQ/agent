// Package config provides configuration validation and utilities.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

// Error returns the error message.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// ValidationErrors represents multiple validation errors.
type ValidationErrors []ValidationError

// Error returns a combined error message.
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}

	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return "validation failed: " + strings.Join(messages, "; ")
}

// IsEmpty returns true if there are no validation errors.
func (e ValidationErrors) IsEmpty() bool {
	return len(e) == 0
}

// Validator provides configuration validation functionality.
type Validator struct {
	errors ValidationErrors
}

// NewValidator creates a new configuration validator.
func NewValidator() *Validator {
	return &Validator{
		errors: make(ValidationErrors, 0),
	}
}

// AddError adds a validation error.
func (v *Validator) AddError(field, message string, value interface{}) {
	v.errors = append(v.errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// Validate returns all validation errors, or nil if validation passed.
func (v *Validator) Validate() error {
	if v.errors.IsEmpty() {
		return nil
	}
	return v.errors
}

// ValidateRequired checks if a required string field is not empty.
func (v *Validator) ValidateRequired(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required", value)
	}
}

// ValidateURL checks if a URL is valid.
func (v *Validator) ValidateURL(field, value string) {
	if value == "" {
		return // Skip validation for empty URLs
	}

	parsedURL, err := url.Parse(value)
	if err != nil {
		v.AddError(field, "is not a valid URL", value)
		return
	}

	if parsedURL.Scheme == "" {
		v.AddError(field, "URL must have a scheme (http/https)", value)
	}

	if parsedURL.Host == "" {
		v.AddError(field, "URL must have a host", value)
	}
}

// ValidateDuration checks if a duration is within acceptable bounds.
func (v *Validator) ValidateDuration(field string, value time.Duration, min, max time.Duration) {
	if value < min {
		v.AddError(field, fmt.Sprintf("must be at least %v", min), value)
	}
	if max > 0 && value > max {
		v.AddError(field, fmt.Sprintf("must be at most %v", max), value)
	}
}

// ValidateRange checks if an integer is within a specified range.
func (v *Validator) ValidateRange(field string, value, min, max int) {
	if value < min {
		v.AddError(field, fmt.Sprintf("must be at least %d", min), value)
	}
	if value > max {
		v.AddError(field, fmt.Sprintf("must be at most %d", max), value)
	}
}

// ValidateAPIKey checks if an API key has the correct format.
func (v *Validator) ValidateAPIKey(field, value string) {
	if value == "" {
		v.AddError(field, "is required", value)
		return
	}

	if !strings.HasPrefix(value, "nw_sk_") {
		v.AddError(field, "must start with 'nw_sk_'", value)
	}

	if len(value) < 20 {
		v.AddError(field, "is too short (minimum 20 characters)", value)
	}
}

// ValidateTenantID checks if a tenant ID has the correct format.
func (v *Validator) ValidateTenantID(field, value string) {
	if value == "" {
		v.AddError(field, "is required", value)
		return
	}

	if len(value) != 10 {
		v.AddError(field, "must be exactly 10 characters long", value)
	}

	// Check if it contains only alphanumeric characters
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			v.AddError(field, "must contain only alphanumeric characters", value)
			break
		}
	}
}

// ValidateLogLevel checks if a log level is valid.
func (v *Validator) ValidateLogLevel(field, value string) {
	validLevels := []string{"debug", "info", "warn", "error"}
	for _, level := range validLevels {
		if value == level {
			return
		}
	}
	v.AddError(field, fmt.Sprintf("must be one of: %s", strings.Join(validLevels, ", ")), value)
}

// ValidateConfig validates the complete configuration using the validator.
func ValidateConfig(c *Config) error {
	validator := NewValidator()

	validator.ValidateTenantID("tenant_id", c.TenantID)
	validator.ValidateAPIKey("api_key", c.APIKey)
	validator.ValidateLogLevel("log_level", c.LogLevel)
	validator.ValidateRange("buffer_max_size", c.Buffer.MaxSize, 100, 10000)

	if c.Collectors.Container {
		if c.Container.StatsInterval > 0 {
			validator.ValidateDuration("container_stats_interval", c.Container.StatsInterval,
				10*time.Second, 10*time.Minute)
		}
	}

	if c.Collectors.VM {
		if c.VM.StatsInterval > 0 {
			validator.ValidateDuration("vm_stats_interval", c.VM.StatsInterval,
				10*time.Second, 10*time.Minute)
		}

		if c.VM.VMTimeout > 0 {
			validator.ValidateDuration("vm_timeout", c.VM.VMTimeout,
				5*time.Second, 2*time.Minute)
		}

		if c.VM.VMCacheTimeout > 0 {
			validator.ValidateDuration("vm_cache_timeout", c.VM.VMCacheTimeout,
				1*time.Minute, 1*time.Hour)
		}

		if c.VM.VMParallelStats > 0 {
			validator.ValidateRange("vm_parallel_stats", c.VM.VMParallelStats, 1, 20)
		}

		// Proxmox API URL validation if provided
		if c.VM.ProxmoxAPI != "" {
			validator.ValidateURL("proxmox_api", c.VM.ProxmoxAPI)
		}
	}

	// Process monitoring validation
	if c.Process.EnableProcessMonitoring {
		if c.Process.ConfigFetchInterval > 0 {
			validator.ValidateDuration("process_config_fetch_interval", c.Process.ConfigFetchInterval,
				1*time.Minute, 1*time.Hour)
		}
	}

	return validator.Validate()
}

// SetDefaults sets default values for optional configuration fields.
func (c *Config) SetDefaults() {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Buffer.MaxSize == 0 {
		c.Buffer.MaxSize = 1000
	}

	if !c.hasCollectorSettings() {
		// Essential collectors - always enabled by default
		c.Collectors.CPU = true
		c.Collectors.Memory = true
		c.Collectors.System = true
		c.Collectors.Disk = true

		// Container collector - will auto-detect Docker/Podman at runtime
		c.Collectors.Container = true

		// VM collector - only relevant on Linux, will be disabled at runtime on other platforms
		c.Collectors.VM = true

		// Optional collectors - disabled by default for security and performance
		// Users must explicitly enable these in config
		// MySQL and PostgreSQL are set via enable_mysql and enable_postgresql
		// Process monitoring is set via enable_process_monitoring
	}

	if c.Container.ContainerRuntime == "" {
		c.Container.ContainerRuntime = "auto"
	}
	if c.Container.StatsInterval == 0 {
		c.Container.StatsInterval = 30 * time.Second
	}

	if c.VM.VMHypervisor == "" {
		c.VM.VMHypervisor = "auto"
	}
	if c.VM.StatsInterval == 0 {
		c.VM.StatsInterval = 30 * time.Second
	}
	if c.VM.VMTimeout == 0 {
		c.VM.VMTimeout = 30 * time.Second
	}
	if c.VM.VMCacheTimeout == 0 {
		c.VM.VMCacheTimeout = 5 * time.Minute
	}
	if c.VM.VMParallelStats == 0 {
		c.VM.VMParallelStats = 3
	}

	if c.Database.MySQLHost == "" {
		c.Database.MySQLHost = "localhost:3306"
	}
	if c.Database.PostgreSQLHost == "" {
		c.Database.PostgreSQLHost = "localhost:5432"
	}
	if c.Database.PostgreSQLDatabase == "" {
		c.Database.PostgreSQLDatabase = "postgres"
	}

	if c.Process.ConfigFetchInterval == 0 {
		c.Process.ConfigFetchInterval = 5 * time.Minute
	}
	if c.Process.ConfigEndpoint == "" {
		c.Process.ConfigEndpoint = "/agent-config/processes"
	}
}

// hasCollectorSettings checks if any collector settings have been explicitly set.
func (c *Config) hasCollectorSettings() bool {
	return c.Collectors.CPU || c.Collectors.Memory || c.Collectors.System ||
		c.Collectors.Disk || c.Collectors.Container || c.Collectors.VM
}

// ValidateAndSetDefaults validates the configuration and sets defaults.
func (c *Config) ValidateAndSetDefaults() error {
	c.SetDefaults()
	return ValidateConfig(c)
}
