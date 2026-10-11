// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/proxy"
)

var (
	proxyTarget      string
	proxyPort        int
	dashboardPort    int
	noDashboard      bool
	dashboardBaseURL string
	allTraffic       bool
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [-- command args...]",
	Args:  cobra.ArbitraryArgs,
	Short: "Start a debugging reverse proxy for OID4VP/VCI flows",
	Long: `Starts a reverse proxy that intercepts, classifies, and decodes OID4VP/VCI
traffic between a wallet and a verifier/issuer. Point your wallet at the proxy
port instead of the target.

Optionally launch the target service as a subprocess by passing its command
after '--'. The proxy scans the service's output for encryption keys
(best-effort), so it decrypts JWE responses of third-party wallets too.

Examples:
  eudi proxy --target http://localhost:8080
  eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
  eudi proxy --target http://localhost:3000 -- npm start`,
	RunE:               runProxy,
	DisableFlagParsing: false,
	TraverseChildren:   true,
}

func init() {
	proxyCmd.Flags().StringVar(&proxyTarget, "target", "", "URL of the verifier/issuer to proxy to (required)")
	proxyCmd.Flags().IntVar(&proxyPort, "port", config.DefaultProxyPort, "Proxy listen port")
	proxyCmd.Flags().IntVar(&dashboardPort, "dashboard", config.DefaultProxyDashboardPort, "Dashboard listen port")
	proxyCmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "Disable web dashboard")
	proxyCmd.Flags().StringVar(&dashboardBaseURL, "dashboard-base-url", "", "Public dashboard URL when a reverse proxy serves it under a path prefix, such as https://example.com/eudi-proxy")
	proxyCmd.Flags().BoolVar(&allTraffic, "all-traffic", false, "Show all traffic, not just OID4VP/VCI requests")
	_ = proxyCmd.MarkFlagRequired("target")
	proxyCmd.AddCommand(proxyLogsCmd())
	rootCmd.AddCommand(proxyCmd)
}

func runProxy(cmd *cobra.Command, args []string) error {
	targetURL, err := url.Parse(proxyTarget)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		return fmt.Errorf("target URL must include a host (e.g. http://localhost:8080)")
	}

	cfg := proxy.Config{
		TargetURL:     targetURL,
		ProxyPort:     proxyPort,
		DashboardPort: dashboardPort,
		NoDashboard:   noDashboard,
		AllTraffic:    allTraffic,
	}

	dashPort := 0
	if !noDashboard {
		dashPort = dashboardPort
	}

	var writer proxy.EntryWriter
	if jsonOutput {
		writer = proxy.NewJSONWriter(allTraffic)
	} else {
		writer = &proxy.TerminalWriter{AllTraffic: allTraffic, DashboardPort: dashPort}
	}

	srv := proxy.NewServer(cfg, writer)

	var dashboard *proxy.Dashboard
	if !noDashboard {
		dashboard = proxy.NewDashboard(srv.Store())
		if err := dashboard.SetBaseURL(dashboardBaseURL); err != nil {
			return fmt.Errorf("--dashboard-base-url: %w", err)
		}
	}

	var scanner *proxy.OutputScanner
	var sub *proxy.Subprocess
	if len(args) > 0 {
		scanner = proxy.NewOutputScanner()
		srv.SetScanner(scanner)

		var subErr error
		sub, subErr = proxy.StartSubprocess(args, scanner, humanOut())
		if subErr != nil {
			return fmt.Errorf("starting service: %w", subErr)
		}
	}

	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)

	cyan.Fprintf(humanOut(), "%s %s\n", config.ProxyName, Version)
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	fmt.Fprintf(humanOut(), "  Target:    %s\n", proxyTarget)
	fmt.Fprintf(humanOut(), "  Proxy:     http://localhost:%d\n", proxyPort)
	if !noDashboard {
		fmt.Fprintf(humanOut(), "  Dashboard: http://localhost:%d\n", dashboardPort)
		if dashboardBaseURL != "" {
			dim.Fprintf(humanOut(), "             %s\n", dashboardBaseURL)
		}
	}
	if len(args) > 0 {
		fmt.Fprintf(humanOut(), "  Service:   %s\n", strings.Join(args, " "))
	}
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	fmt.Fprintln(humanOut())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var dashboardServer *http.Server
	if dashboard != nil {
		dashboardServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", dashboardPort),
			Handler:      dashboard.Handler(),
			ReadTimeout:  config.ServerReadTimeout,
			WriteTimeout: config.ServerWriteTimeout,
			IdleTimeout:  config.ServerIdleTimeout,
		}
		go func() {
			if err := dashboardServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(humanOut(), "Dashboard error: %v\n", err)
			}
		}()
	}

	proxyServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", proxyPort),
		Handler: srv,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.ServerWriteTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
	}

	// A subprocess exit leaves the proxy running for inspection.
	if sub != nil {
		go func() {
			if err := sub.Wait(); err != nil {
				fmt.Fprintf(humanOut(), "\nService exited: %v\n", err)
			} else {
				fmt.Fprintln(humanOut(), "\nService exited")
			}
		}()
	}

	go func() {
		<-sigCh
		fmt.Fprintln(humanOut(), "\nShutting down...")

		if sub != nil {
			sub.Stop()
		}
		if dashboardServer != nil {
			dashboardServer.Close()
		}
		proxyServer.Close()

		<-sigCh
		fmt.Fprintln(humanOut(), "\nForce exit")
		os.Exit(1)
	}()

	err = proxyServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		if sub != nil {
			_ = sub.Wait()
		}
		return nil
	}
	// The proxy did not start, for example because the port was busy. The
	// launched service runs in its own process group and outlives this command
	// unless it is stopped here.
	if sub != nil {
		sub.Stop()
		_ = sub.Wait()
	}
	if dashboardServer != nil {
		dashboardServer.Close()
	}
	return err
}
