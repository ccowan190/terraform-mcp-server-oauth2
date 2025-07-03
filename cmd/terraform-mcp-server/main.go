// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/terraform-mcp-server/pkg/oauth2"
	"github.com/hashicorp/terraform-mcp-server/version"

	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     "terraform-mcp-server",
		Short:   "Terraform MCP Server",
		Long:    `A Terraform MCP server that handles various tools and resources.`,
		Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version.GetHumanVersion(), version.GitCommit, version.BuildDate),
		Run:     runDefaultCommand,
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		Run: func(_ *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			if err := runStdioServer(logger); err != nil {
				stdlog.Fatal("failed to run stdio server:", err)
			}
		},
	}

	httpCmd = &cobra.Command{
		Use:   "http",
		Short: "Start StreamableHTTP server",
		Long:  `Start a server that communicates via StreamableHTTP transport on port 8080 at /mcp endpoint.`,
		Run: func(cmd *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			port, err := cmd.Flags().GetString("transport-port")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP port:", err)
			}
			host, err := cmd.Flags().GetString("transport-host")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP host:", err)
			}

			if err := runHTTPServer(logger, host, port); err != nil {
				stdlog.Fatal("failed to run streamableHTTP server:", err)
			}
		},
	}
)

func runHTTPServer(logger *log.Logger, host string, port string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hcServer := NewServer(version.Version)
	registryInit(hcServer, logger)

	return httpServerInit(ctx, hcServer, logger, host, port)
}

func httpServerInit(ctx context.Context, hcServer *server.MCPServer, logger *log.Logger, host string, port string) error {
	// Initialize OAuth2 handler
	oauth2Handler, err := oauth2.NewOAuth2Handler(logger)
	if err != nil {
		logger.Warnf("OAuth2 not configured: %v. Falling back to IAM authentication.", err)
		oauth2Handler = nil
	}

	// Create StreamableHTTP server which implements the new streamable-http transport
	// This is the modern MCP transport that supports both direct HTTP responses and SSE streams
	streamableServer := server.NewStreamableHTTPServer(hcServer,
		server.WithEndpointPath("/mcp"), // Default MCP endpoint path
		server.WithLogger(logger),
	)

	mux := http.NewServeMux()

	// Add OAuth2 endpoints if configured
	if oauth2Handler != nil {
		logger.Info("OAuth2 authentication enabled")
		mux.HandleFunc("/oauth/login", oauth2Handler.HandleAuth)
		mux.HandleFunc("/oauth/callback", oauth2Handler.HandleCallback)
		
		// Wrap MCP endpoints with OAuth2 authentication
		mux.Handle("/mcp", oauth2Handler.AuthMiddleware(streamableServer))
		mux.Handle("/mcp/", oauth2Handler.AuthMiddleware(streamableServer))
	} else {
		logger.Info("OAuth2 not configured - using IAM authentication")
		// Handle the /mcp endpoint without OAuth2 authentication (relies on Cloud Run IAM)
		mux.Handle("/mcp", streamableServer)
		mux.Handle("/mcp/", streamableServer)
	}

	// Add health check endpoint (always public)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		authStatus := "iam"
		if oauth2Handler != nil {
			authStatus = "oauth2"
		}
		w.Write([]byte(fmt.Sprintf(`{"status":"ok","service":"terraform-mcp-server","transport":"streamable-http","auth":"%s"}`, authStatus)))
	})

	// Add authentication status endpoint
	mux.HandleFunc("/auth/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if oauth2Handler != nil {
			w.Write([]byte(`{"auth_type":"oauth2","auth_enabled":true,"login_url":"/oauth/login"}`))
		} else {
			w.Write([]byte(`{"auth_type":"iam","auth_enabled":true,"login_url":null}`))
		}
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in goroutine
	errC := make(chan error, 1)
	go func() {
		if oauth2Handler != nil {
			logger.Infof("Starting StreamableHTTP server with OAuth2 authentication on %s/mcp", addr)
		} else {
			logger.Infof("Starting StreamableHTTP server with IAM authentication on %s/mcp", addr)
		}
		errC <- httpServer.ListenAndServe()
	}()

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logger.Infof("Shutting down StreamableHTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errC:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("StreamableHTTP server error: %w", err)
		}
	}

	return nil
}

func runStdioServer(logger *log.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hcServer := NewServer(version.Version)
	registryInit(hcServer, logger)

	return serverInit(ctx, hcServer, logger)
}

func NewServer(version string, opts ...server.ServerOption) *server.MCPServer {
	// Add default options
	defaultOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	}
	opts = append(defaultOpts, opts...)

	// Create a new MCP server
	s := server.NewMCPServer(
		"terraform-mcp-server",
		version,
		opts...,
	)
	return s
}

// runDefaultCommand handles the default behavior when no subcommand is provided
func runDefaultCommand(cmd *cobra.Command, _ []string) {
	// Default to stdio mode when no subcommand is provided
	logFile, err := cmd.PersistentFlags().GetString("log-file")
	if err != nil {
		stdlog.Fatal("Failed to get log file:", err)
	}
	logger, err := initLogger(logFile)
	if err != nil {
		stdlog.Fatal("Failed to initialize logger:", err)
	}

	if err := runStdioServer(logger); err != nil {
		stdlog.Fatal("failed to run stdio server:", err)
	}
}

func main() {
	// Check environment variables first - they override command line args
	if shouldUseHTTPMode() {
		port := getHTTPPort()
		host := "0.0.0.0"

		logFile, _ := rootCmd.PersistentFlags().GetString("log-file")
		logger, err := initLogger(logFile)
		if err != nil {
			stdlog.Fatal("Failed to initialize logger:", err)
		}

		if err := runHTTPServer(logger, host, port); err != nil {
			stdlog.Fatal("failed to run HTTP server:", err)
		}
		return
	}

	// Fall back to normal CLI behavior
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// shouldUseHTTPMode checks if environment variables indicate HTTP mode
func shouldUseHTTPMode() bool {
	return os.Getenv("TRANSPORT_MODE") == "http" || os.Getenv("TRANSPORT_PORT") != ""
}

// getHTTPPort returns the port from environment variables or default
func getHTTPPort() string {
	if port := os.Getenv("TRANSPORT_PORT"); port != "" {
		return port
	}
	return "8080"
}
