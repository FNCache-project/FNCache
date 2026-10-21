package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("ONCACHE_CONFIG", "")
	t.Setenv("ONCACHE_NODE_NAME", "node-a")
	t.Setenv("ONCACHE_LOG_LEVEL", "debug")
	t.Setenv("ONCACHE_INSTALLATION_ID", "install-a")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "node-a" || cfg.LogLevel != "debug" || cfg.InstallationID != "install-a" {
		t.Fatalf("environment overrides not applied: %+v", cfg)
	}
}

func TestLoadPreservesDisabledFeature(t *testing.T) {
	t.Setenv("ONCACHE_NODE_NAME", "node-a")
	t.Setenv("ONCACHE_LOG_LEVEL", "info")
	path := writeConfig(t, "nodeName: node-a\nfeatures:\n  enabled: false\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Features.Enabled {
		t.Fatal("features.enabled=false was not preserved")
	}
}

func TestLoadPreservesCleanupOnShutdown(t *testing.T) {
	t.Setenv("ONCACHE_NODE_NAME", "node-a")
	path := writeConfig(t, "nodeName: node-a\nfeatures:\n  cleanupOnShutdown: true\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Features.CleanupOnShutdown {
		t.Fatal("features.cleanupOnShutdown=true was not preserved")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\nunknown: true\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadRejectsDangerousPath(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\npinRoot: /sys/fs/bpf/oncache\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected pinRoot validation error")
	}
}

func TestLoadRejectsHeartbeatConstraint(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\nheartbeat:\n  interval: 2s\n  timeout: 5s\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected heartbeat validation error")
	}
}

func TestLoadRejectsUnsupportedLogLevel(t *testing.T) {
	t.Setenv("ONCACHE_LOG_LEVEL", "trace")
	if _, err := Load(""); err == nil {
		t.Fatal("unsupported log level was accepted")
	}
}

func TestLoadRejectsMissingDynamicDatapathIdentity(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\ndatapath:\n  elfPath: /opt/oncache/bpf/tc_prog_kern.o\n  elfBuildID: \"\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("missing ELF build ID was accepted")
	}
}

func TestLoadPreservesCustomMapCapacities(t *testing.T) {
	t.Setenv("ONCACHE_NODE_NAME", "node-a")
	t.Setenv("ONCACHE_LOG_LEVEL", "info")
	path := writeConfig(t, `nodeName: node-a
maps:
  ingressCacheMaxEntries: 2048
  egressIPCacheMaxEntries: 8192
  egressCacheMaxEntries: 2048
  policyCacheMaxEntries: 8192
  devMapMaxEntries: 16
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := MapConfig{IngressCacheMaxEntries: 2048, EgressIPCacheMaxEntries: 8192, EgressCacheMaxEntries: 2048, PolicyCacheMaxEntries: 8192, DevMapMaxEntries: 16}
	if cfg.Maps != want {
		t.Fatalf("custom Map capacities were not preserved: got=%+v want=%+v", cfg.Maps, want)
	}
}

func TestDefaultsAndValidationIncludeResyncInterval(t *testing.T) {
	cfg := defaults()
	if cfg.RuntimeEndpoint != "auto" {
		t.Fatalf("runtime endpoint default = %q, want auto", cfg.RuntimeEndpoint)
	}
	if time.Duration(cfg.Kube.ResyncInterval) != 30*time.Minute {
		t.Fatalf("resync default = %v", cfg.Kube.ResyncInterval)
	}
	cfg.NodeName = "node-a"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Kube.ResyncInterval = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero resync interval was accepted")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
