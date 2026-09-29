package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cat-cc-Lcos/FNCache/internal/agent"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func main() {
	manifest := flag.String("static-config", "", "path to a StaticRuntimeConfiguration manifest")
	once := flag.Bool("once", false, "reconcile once and exit without renewing the heartbeat lease")
	flag.Parse()
	if *manifest == "" {
		fmt.Fprintln(os.Stderr, "-static-config is required")
		os.Exit(2)
	}
	if err := run(*manifest, *once); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, once bool) (err error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config, err := agent.LoadStaticRuntimeManifest(path)
	if err != nil {
		return err
	}
	runtime, err := agent.NewStaticRuntime(ctx, config)
	if err != nil {
		return fmt.Errorf("create static runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close static runtime: %w", closeErr)
		}
	}()
	var result reconcile.ReconcileResult
	if once {
		result, err = runtime.RunOnce(ctx)
	} else {
		result, err = runtime.Run(ctx)
	}
	if err != nil {
		return fmt.Errorf("run static runtime: %w", err)
	}
	if once && result.State != reconcile.AgentDisabled {
		return fmt.Errorf("one-shot reconciliation did not leave fast path disabled: %s", result.State)
	}
	return nil
}
