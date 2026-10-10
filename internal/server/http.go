package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type Config struct {
	ListenAddress string
}

type Server struct {
	http     *http.Server
	listener net.Listener
}

func New(config Config, handler http.Handler) (*Server, error) {
	if config.ListenAddress == "" || handler == nil {
		return nil, fmt.Errorf("HTTP listen address and handler are required")
	}
	s := &Server{}
	s.http = &http.Server{Handler: handler, Addr: config.ListenAddress, ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

func (s *Server) Start() error {
	if s.listener != nil {
		return fmt.Errorf("HTTP server is already started")
	}
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.listener = listener
	go func() { _ = s.http.Serve(listener) }()
	return nil
}

func (s *Server) Close(ctx context.Context) error {
	if s.listener == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}
