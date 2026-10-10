package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/agent"
	"github.com/cat-cc-Lcos/FNCache/internal/cleanup"
	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/server"
)

func main() {
	manifest := flag.String("static-config", "", "path to a StaticRuntimeConfiguration manifest")
	configPath := flag.String("config", "", "path to an AgentConfiguration for dynamic Kubernetes mode")
	cleanupMode := flag.Bool("cleanup", false, "remove ONCache objects using ownership evidence")
	dryRun := flag.Bool("dry-run", false, "print a cleanup plan without changing the node")
	flag.Parse()
	logger, loggerErr := observability.NewFromEnvironment("oncache-agent")
	if loggerErr != nil {
		fmt.Fprintln(os.Stderr, loggerErr)
		os.Exit(2)
	}
	if *cleanupMode {
		if *manifest != "" || *configPath == "" {
			logger.Error(context.Background(), "invalid cleanup command line", "error", "-cleanup requires -config and cannot use -static-config")
			os.Exit(2)
		}
	} else if *dryRun || (*manifest == "") == (*configPath == "") {
		logger.Error(context.Background(), "invalid command line", "error", "exactly one of -static-config or -config is required")
		os.Exit(2)
	}
	var err error
	if *cleanupMode {
		err = runCleanup(*configPath, *dryRun)
	} else if *manifest != "" {
		err = run(*manifest)
	} else {
		err = runDynamic(*configPath)
	}
	if err != nil {
		logger.Error(context.Background(), "agent exited", "error", err.Error())
		os.Exit(1)
	}
}

func runCleanup(path string, dryRun bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load cleanup configuration: %w", err)
	}
	plan, runErr := cleanup.Run(context.Background(), cleanup.Options{
		PinRoot: cfg.PinRoot, StatePath: filepath.Join(cfg.StateDir, "state.json"), InstallationID: cfg.InstallationID,
		MarkerChain: cfg.Markers.Chain, MarkerComment: cfg.Markers.Comment,
		MapCapacities: datapath.MapCapacities{
			IngressCacheMaxEntries: cfg.Maps.IngressCacheMaxEntries, EgressIPCacheMaxEntries: cfg.Maps.EgressIPCacheMaxEntries,
			EgressCacheMaxEntries: cfg.Maps.EgressCacheMaxEntries, PolicyCacheMaxEntries: cfg.Maps.PolicyCacheMaxEntries,
			DevMapMaxEntries: cfg.Maps.DevMapMaxEntries,
		},
	}, dryRun)
	data, marshalErr := json.MarshalIndent(plan, "", "  ")
	if marshalErr == nil {
		fmt.Println(string(data))
	}
	return errors.Join(runErr, marshalErr)
}

func runDynamic(path string) error {
	runtime, err := agent.NewDynamicRuntime(path)
	if err != nil {
		return fmt.Errorf("create dynamic runtime: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handler, err := observability.NewHandler(observability.HandlerConfig{DebugState: runtime.DebugStateEnabled()}, runtime)
	if err != nil {
		return fmt.Errorf("create observability handler: %w", err)
	}
	httpServer, err := server.New(server.Config{ListenAddress: runtime.HTTPAddress()}, handler)
	if err != nil {
		return fmt.Errorf("create HTTP server: %w", err)
	}
	if err := httpServer.Start(); err != nil {
		return fmt.Errorf("start HTTP server: %w", err)
	}
	runErr := runtime.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return errors.Join(runErr, httpServer.Close(shutdownCtx))
}

func run(path string) (err error) {
	config, err := agent.LoadStaticRuntimeManifest(path)
	if err != nil {
		return err
	}
	runtime, err := agent.NewStaticRuntime(context.Background(), config)
	if err != nil {
		return fmt.Errorf("create static runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close static runtime: %w", closeErr)
		}
	}()
	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		return fmt.Errorf("run static reconciliation: %w", err)
	}
	if !staticReconcileSucceeded(result.State) {
		return fmt.Errorf("static reconciliation did not reach Ready: %s", result.State)
	}
	return nil
}

func staticReconcileSucceeded(state reconcile.AgentState) bool {
	return state == reconcile.AgentReady || state == reconcile.AgentDisabled
}
