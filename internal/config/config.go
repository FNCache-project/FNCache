package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(value)
	return nil
}

type AgentConfiguration struct {
	APIVersion      string          `yaml:"apiVersion"`
	Kind            string          `yaml:"kind"`
	NodeName        string          `yaml:"nodeName"`
	RuntimeEndpoint string          `yaml:"runtimeEndpoint"`
	PinRoot         string          `yaml:"pinRoot"`
	StateDir        string          `yaml:"stateDir"`
	Datapath        DatapathConfig  `yaml:"datapath"`
	Overlay         OverlayConfig   `yaml:"overlay"`
	Markers         MarkerConfig    `yaml:"markers"`
	Heartbeat       HeartbeatConfig `yaml:"heartbeat"`
	Kube            KubeConfig      `yaml:"kube"`
	Health          HealthConfig    `yaml:"health"`
	Scan            ScanConfig      `yaml:"scan"`
	Maps            MapConfig       `yaml:"maps"`
	Server          ServerConfig    `yaml:"server"`
	Features        FeatureConfig   `yaml:"features"`
	LogLevel        string          `yaml:"-"`
	InstallationID  string          `yaml:"-"`
}

type OverlayConfig struct {
	Type          string `yaml:"type"`
	Device        string `yaml:"device"`
	VXLANLinkName string `yaml:"vxlanLinkName"`
}

type DatapathConfig struct {
	ELFPath    string `yaml:"elfPath"`
	ELFBuildID string `yaml:"elfBuildID"`
}

type MarkerConfig struct {
	Chain           string `yaml:"chain"`
	Comment         string `yaml:"comment"`
	MissMask        uint8  `yaml:"missMask"`
	EstablishedMask uint8  `yaml:"establishedMask"`
}

type HeartbeatConfig struct {
	Interval Duration `yaml:"interval"`
	Timeout  Duration `yaml:"timeout"`
}

type KubeConfig struct {
	MaxStaleness   Duration `yaml:"maxStaleness"`
	ResyncInterval Duration `yaml:"resyncInterval"`
}

type HealthConfig struct {
	Interval Duration `yaml:"interval"`
}

type ScanConfig struct {
	IncrementalInterval Duration `yaml:"incrementalInterval"`
	FullInterval        Duration `yaml:"fullInterval"`
}

type MapConfig struct {
	IngressCacheMaxEntries  uint32 `yaml:"ingressCacheMaxEntries"`
	EgressIPCacheMaxEntries uint32 `yaml:"egressIPCacheMaxEntries"`
	EgressCacheMaxEntries   uint32 `yaml:"egressCacheMaxEntries"`
	PolicyCacheMaxEntries   uint32 `yaml:"policyCacheMaxEntries"`
	DevMapMaxEntries        uint32 `yaml:"devMapMaxEntries"`
}

type ServerConfig struct {
	ListenAddress string `yaml:"listenAddress"`
}

type FeatureConfig struct {
	Enabled    bool `yaml:"enabled"`
	DebugState bool `yaml:"debugState"`
}

func Load(path string) (AgentConfiguration, error) {
	cfg := defaults()
	if path == "" {
		path = os.Getenv("ONCACHE_CONFIG")
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return AgentConfiguration{}, fmt.Errorf("read config: %w", err)
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return AgentConfiguration{}, fmt.Errorf("decode config: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				return AgentConfiguration{}, fmt.Errorf("config contains multiple YAML documents")
			}
			return AgentConfiguration{}, fmt.Errorf("decode config: %w", err)
		}
	}
	applyEnvironment(&cfg)
	if err := cfg.Validate(); err != nil {
		return AgentConfiguration{}, err
	}
	return cfg, nil
}

func (c AgentConfiguration) Validate() error {
	if c.APIVersion != "oncache.io/v1alpha1" || c.Kind != "AgentConfiguration" {
		return fmt.Errorf("unsupported apiVersion/kind: %s/%s", c.APIVersion, c.Kind)
	}
	if c.NodeName == "" || c.RuntimeEndpoint == "" {
		return fmt.Errorf("nodeName and runtimeEndpoint are required")
	}
	if c.Overlay.Type != "flannel-vxlan" || c.Overlay.Device == "" || c.Overlay.VXLANLinkName == "" {
		return fmt.Errorf("overlay must be flannel-vxlan with device and VXLAN link")
	}
	if c.Datapath.ELFPath == "" || !filepath.IsAbs(c.Datapath.ELFPath) || c.Datapath.ELFBuildID == "" {
		return fmt.Errorf("datapath ELF path and build ID are required")
	}
	if c.Markers.Chain == "" || c.Markers.Comment == "" {
		return fmt.Errorf("marker chain and comment are required")
	}
	if c.Markers.MissMask != 0x04 || c.Markers.EstablishedMask != 0x08 {
		return fmt.Errorf("markers must use missMask 0x04 and establishedMask 0x08")
	}
	interval, timeout := time.Duration(c.Heartbeat.Interval), time.Duration(c.Heartbeat.Timeout)
	if interval <= 0 || timeout < 3*interval || timeout > 60*time.Second {
		return fmt.Errorf("heartbeat timeout must be 3x interval and no more than 60s")
	}
	if time.Duration(c.Health.Interval) <= 0 || time.Duration(c.Kube.MaxStaleness) < time.Duration(c.Health.Interval) || time.Duration(c.Kube.ResyncInterval) <= 0 {
		return fmt.Errorf("kube intervals are invalid")
	}
	if time.Duration(c.Scan.IncrementalInterval) <= 0 || time.Duration(c.Scan.FullInterval) < time.Duration(c.Scan.IncrementalInterval) {
		return fmt.Errorf("scan intervals are invalid")
	}
	if c.Maps.IngressCacheMaxEntries == 0 || c.Maps.EgressIPCacheMaxEntries == 0 || c.Maps.EgressCacheMaxEntries == 0 || c.Maps.PolicyCacheMaxEntries == 0 || c.Maps.DevMapMaxEntries == 0 {
		return fmt.Errorf("map capacities must be greater than zero")
	}
	if !validPinRoot(c.PinRoot) {
		return fmt.Errorf("pinRoot must be below /sys/fs/bpf/oncache/")
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) == "/" {
		return fmt.Errorf("stateDir must be a dedicated absolute directory")
	}
	if c.Server.ListenAddress == "" {
		return fmt.Errorf("server.listenAddress is required")
	}
	if _, err := observability.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("log level is invalid: %w", err)
	}
	return nil
}

func defaults() AgentConfiguration {
	return AgentConfiguration{
		APIVersion: "oncache.io/v1alpha1", Kind: "AgentConfiguration", RuntimeEndpoint: "unix:///run/containerd/containerd.sock",
		PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", Datapath: DatapathConfig{ELFPath: "/opt/oncache/bpf/tc_prog_kern.o", ELFBuildID: "sha256:dev"}, Overlay: OverlayConfig{Type: "flannel-vxlan", Device: "auto", VXLANLinkName: "flannel.1"},
		Markers: MarkerConfig{Chain: "ONCACHE", Comment: "oncache:dev", MissMask: 0x04, EstablishedMask: 0x08}, Heartbeat: HeartbeatConfig{Interval: Duration(time.Second), Timeout: Duration(5 * time.Second)},
		Kube: KubeConfig{MaxStaleness: Duration(30 * time.Second), ResyncInterval: Duration(30 * time.Minute)}, Health: HealthConfig{Interval: Duration(5 * time.Second)},
		Scan:   ScanConfig{IncrementalInterval: Duration(30 * time.Second), FullInterval: Duration(5 * time.Minute)},
		Maps:   MapConfig{IngressCacheMaxEntries: 1024, EgressIPCacheMaxEntries: 4096, EgressCacheMaxEntries: 1024, PolicyCacheMaxEntries: 4096, DevMapMaxEntries: 8},
		Server: ServerConfig{ListenAddress: ":9090"}, Features: FeatureConfig{Enabled: true}, LogLevel: "info",
	}
}

func applyEnvironment(c *AgentConfiguration) {
	if value, ok := os.LookupEnv("ONCACHE_NODE_NAME"); ok {
		c.NodeName = value
	}
	if value, ok := os.LookupEnv("ONCACHE_LOG_LEVEL"); ok {
		c.LogLevel = value
	}
	if value, ok := os.LookupEnv("ONCACHE_INSTALLATION_ID"); ok {
		c.InstallationID = value
	}
}

func validPinRoot(path string) bool {
	clean := filepath.Clean(path)
	root := string(filepath.Separator) + "sys/fs/bpf/oncache/"
	base := strings.TrimSuffix(root, string(filepath.Separator))
	return filepath.IsAbs(clean) && clean != base && strings.HasPrefix(clean+string(filepath.Separator), root)
}
