// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type DynamicInstrumentationConfig struct {
	Enabled              bool                         `yaml:"enabled" env:"OTEL_EBPF_DYNAMIC_INSTRUMENTATION_ENABLED"`
	ListenAddress        string                       `yaml:"listen_address" env:"OTEL_EBPF_DYNAMIC_INSTRUMENTATION_LISTEN_ADDRESS"`
	TTL                  time.Duration                `yaml:"ttl"`
	WatchInterval        time.Duration                `yaml:"watch_interval"`
	RequestTimeout       time.Duration                `yaml:"request_timeout"`
	SymbolCacheEntries   int                          `yaml:"symbol_cache_entries"`
	SymbolCacheBytes     int64                        `yaml:"symbol_cache_bytes"`
	MaxCachedBinaryBytes int64                        `yaml:"max_cached_binary_bytes"`
	MaxProbes            int                          `yaml:"max_probes"`
	Rules                []DynamicInstrumentationRule `yaml:"rules"`
}

type DynamicInstrumentationRule struct {
	Service services.GlobDefinitionCriteria `yaml:"service"`
	Spans   []CustomSpanSpec                `yaml:"spans"`
	Patches []PatchSpec                     `yaml:"patches"`
}

const (
	PatchActionReturn = "return"
	PatchModeEnforce  = "enforce"
	PatchModeObserve  = "observe"
	MaxPatchTTL       = 24 * time.Hour

	// MaxPredicateContainsBytes bounds the literal of an observe predicate.
	MaxPredicateContainsBytes = 256
	// MaxPredicateArgument is the highest argument index a predicate may read (a JVM method has at
	// most 255 parameter slots).
	MaxPredicateArgument = 254
)

var (
	patchLoaderSelector = regexp.MustCompile(`^loader:(bootstrap|[0-9]{1,18})$`)
	sha256Hex           = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// PatchSpec makes one Java method return a constant String until its TTL ends. The descriptor
// is required so overloads are never patched by accident.
type PatchSpec struct {
	Class      string        `yaml:"class"`
	Method     string        `yaml:"method"`
	Descriptor string        `yaml:"descriptor"`
	Action     string        `yaml:"action"`
	Value      string        `yaml:"value"`
	TTL        time.Duration `yaml:"ttl"`
	// Loader selects one class loader of the target JVM ("loader:<n>"); the agent lists the
	// candidates when more than one loader defines the class. ArtifactSHA256 is the SHA-256 of
	// the jar the class was loaded from and Fingerprint is the canonical-v1 fingerprint of the
	// method (64 hex digits each). Whatever is set is verified; a mismatch refuses the patch.
	Loader         string `yaml:"loader"`
	ArtifactSHA256 string `yaml:"artifact_sha256"`
	Fingerprint    string `yaml:"fingerprint"`
	// RequireIdentity refuses the patch unless loader, artifact_sha256 and fingerprint are all set.
	RequireIdentity bool `yaml:"require_identity"`
	// Mode is "enforce" (the default: return Value) or "observe": count the calls of the exact
	// method without changing it. Counters come back in the rule status, where "unknown" (no or
	// vanished counters) is never shown as zero.
	Mode string `yaml:"mode"`
	// Predicate, observe mode only, also counts the calls whose String argument contains a
	// literal. It is a test-only closed form: one parameter, one literal, no pattern language.
	Predicate *PatchPredicate `yaml:"predicate"`
}

// PatchPredicate counts a call as a hit when the String parameter at Argument (0 is the first
// parameter, never the receiver) contains Contains.
type PatchPredicate struct {
	Argument int    `yaml:"argument"`
	Contains string `yaml:"contains"`
}

// Observing reports whether the patch only counts calls.
func (p *PatchSpec) Observing() bool {
	return p.Mode == PatchModeObserve
}

func (p *PatchSpec) Target() string {
	return p.Class + "." + p.Method + p.Descriptor
}

// Key identifies one patch slot in a process: the method plus the class loader it is aimed at.
// The same method in two loaders is two slots, so they can be patched, expired and removed
// independently.
func (p *PatchSpec) Key() string {
	return p.Target() + "@" + p.Loader
}

func (p *PatchSpec) Validate() error {
	if p.Class == "" || p.Method == "" || p.Descriptor == "" {
		return errors.New("patch class, method and descriptor are required")
	}
	if p.Mode != "" && p.Mode != PatchModeEnforce && p.Mode != PatchModeObserve {
		return fmt.Errorf("patch %s: mode must be %q or %q", p.Target(), PatchModeEnforce, PatchModeObserve)
	}
	if p.Observing() {
		// Counting works for any method; an observing patch never returns a value.
		if !strings.HasPrefix(p.Descriptor, "(") || !strings.Contains(p.Descriptor, ")") {
			return fmt.Errorf("patch %s: descriptor must be a JVM method descriptor", p.Target())
		}
		if p.Action != "" && p.Action != PatchActionReturn {
			return fmt.Errorf("patch %s: action must be empty or %q in observe mode", p.Target(), PatchActionReturn)
		}
		if p.Value != "" {
			return fmt.Errorf("patch %s: value is not used in observe mode", p.Target())
		}
	} else {
		if !strings.HasPrefix(p.Descriptor, "(") || !strings.HasSuffix(p.Descriptor, ")Ljava/lang/String;") {
			return fmt.Errorf("patch %s: descriptor must be a JVM method descriptor returning java.lang.String", p.Target())
		}
		if p.Action != PatchActionReturn {
			return fmt.Errorf("patch %s: action must be %q", p.Target(), PatchActionReturn)
		}
		if p.Predicate != nil {
			return fmt.Errorf("patch %s: predicate needs mode %q", p.Target(), PatchModeObserve)
		}
	}
	if p.Predicate != nil {
		if p.Predicate.Argument < 0 || p.Predicate.Argument > MaxPredicateArgument {
			return fmt.Errorf("patch %s: predicate argument must be between 0 and %d", p.Target(), MaxPredicateArgument)
		}
		if p.Predicate.Contains == "" || len(p.Predicate.Contains) > MaxPredicateContainsBytes {
			return fmt.Errorf("patch %s: predicate contains must be 1 to %d bytes", p.Target(), MaxPredicateContainsBytes)
		}
	}
	if p.TTL <= 0 || p.TTL > MaxPatchTTL {
		return fmt.Errorf("patch %s: ttl must be between 0 and %s", p.Target(), MaxPatchTTL)
	}
	if p.Loader != "" && !patchLoaderSelector.MatchString(p.Loader) {
		return fmt.Errorf("patch %s: loader must look like loader:<number> or loader:bootstrap", p.Target())
	}
	if p.ArtifactSHA256 != "" && !sha256Hex.MatchString(p.ArtifactSHA256) {
		return fmt.Errorf("patch %s: artifact_sha256 must be 64 hexadecimal digits", p.Target())
	}
	if p.Fingerprint != "" && !sha256Hex.MatchString(p.Fingerprint) {
		return fmt.Errorf("patch %s: fingerprint must be 64 hexadecimal digits", p.Target())
	}
	if p.RequireIdentity && (p.Loader == "" || p.ArtifactSHA256 == "" || p.Fingerprint == "") {
		return fmt.Errorf("patch %s: require_identity needs loader, artifact_sha256 and fingerprint", p.Target())
	}
	return nil
}

func (c *DynamicInstrumentationConfig) IsEnabled() bool {
	return c.Enabled || c.ListenAddress != "" || len(c.Rules) != 0
}

func (c *DynamicInstrumentationConfig) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.TTL <= 0 || c.WatchInterval <= 0 || c.RequestTimeout <= 0 {
		return errors.New("dynamic_instrumentation: ttl, watch_interval and request_timeout must be positive")
	}
	if c.SymbolCacheEntries < 0 || c.SymbolCacheBytes < 0 || c.MaxCachedBinaryBytes < 0 || c.MaxProbes <= 0 || c.MaxProbes > 1<<20 {
		return errors.New("dynamic_instrumentation: cache limits must be nonnegative and max_probes must be between 1 and 1048576")
	}
	if c.ListenAddress != "" {
		_, _, err := net.SplitHostPort(c.ListenAddress)
		if err != nil {
			return fmt.Errorf("dynamic_instrumentation.listen_address: %w", err)
		}
	}
	for i := range c.Rules {
		if err := c.Rules[i].Validate(); err != nil {
			return fmt.Errorf("dynamic_instrumentation.rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *DynamicInstrumentationRule) Validate() error {
	if len(r.Service) == 0 {
		return errors.New("service must contain at least one selector")
	}
	if err := r.Service.Validate(); err != nil {
		return err
	}
	if len(r.Spans) == 0 && len(r.Patches) == 0 {
		return errors.New("spans or patches must not be empty")
	}
	for i := range r.Patches {
		if err := r.Patches[i].Validate(); err != nil {
			return err
		}
	}
	c := CustomSpanConfig{TTL: CustomSpanDefaultTTL, Spans: r.Spans}
	if err := c.Validate(); err != nil {
		return err
	}
	for _, span := range r.Spans {
		if span.IsAnyFunction() {
			if _, err := glob.Compile(span.FunctionSymbol()); err != nil {
				return fmt.Errorf("function glob: %w", err)
			}
		}
	}
	return nil
}

func DefaultDynamicInstrumentationConfig() DynamicInstrumentationConfig {
	return DynamicInstrumentationConfig{TTL: CustomSpanDefaultTTL, WatchInterval: time.Second, RequestTimeout: 10 * time.Second, SymbolCacheEntries: 32, SymbolCacheBytes: 64 << 20, MaxCachedBinaryBytes: 8 << 20, MaxProbes: 1024}
}
