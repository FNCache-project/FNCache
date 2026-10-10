package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestNewRequiresListenAddressAndHandler(t *testing.T) {
	tests := []struct {
		name    string
		address string
		handler http.Handler
	}{
		{name: "missing address", handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "missing handler", address: "127.0.0.1:0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(Config{ListenAddress: test.address}, test.handler); err == nil {
				t.Fatal("server accepted incomplete configuration")
			}
		})
	}
}

func TestServerLifecycle(t *testing.T) {
	server, err := New(Config{ListenAddress: "127.0.0.1:0"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("close before start: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil {
		t.Fatal("server allowed a second start")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Close(shutdownCtx); err != nil {
		t.Fatalf("close: %v", err)
	}
}
