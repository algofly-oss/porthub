package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/algofly-oss/porthub/client/internal/agent"
	"github.com/algofly-oss/porthub/client/internal/download"
	"github.com/algofly-oss/porthub/client/internal/fileserver"
	"github.com/algofly-oss/porthub/client/internal/relay"
	"github.com/algofly-oss/porthub/client/internal/service"
	"github.com/algofly-oss/porthub/client/internal/supervise"
	"github.com/algofly-oss/porthub/client/internal/tunnel"
)

var version = "development"

const usage = `usage: porthub <command>
  http.server [port] [path] [--bind ADDRESS]   serve files (HTTP Range supported)
  http.server stop [PORT|--all]                stop servers from any terminal
  http.server list                             list running servers
  tunnel --config client.toml                  public port tunnels (rathole protocol)
  service install --profile FILE | uninstall | status   boot-time service
  relay-server [--listen ADDR]                 gateway relay (PORTHUB_RELAY_SECRET)
  get <http(s)-url>                            parallel, resumable download
  enroll --server URL --profile FILE           private network enrollment
  run --profile FILE                           run the private network client
  version`

// httpServer accepts the shell client's forms: [port] [path], -p/--port,
// --path, --bind, plus "stop" and "list".
func httpServer(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "list" {
		records, err := fileserver.List()
		if err != nil {
			return err
		}
		for _, r := range records {
			fmt.Printf("port %d  bind %s  pid %d  since %s  %s\n", r.Port, r.Bind, r.PID, r.Started.Format(time.RFC3339), r.Root)
		}
		for _, l := range fileserver.FindLegacy() {
			fmt.Printf("port %d  legacy lighttpd  pid %d\n", l.Port, l.PID)
		}
		return nil
	}
	if len(args) > 0 && args[0] == "stop" {
		port := 0
		if len(args) != 2 {
			return errors.New("usage: porthub http.server stop PORT|--all")
		}
		if args[1] != "--all" {
			p, err := strconv.Atoi(args[1])
			if err != nil || p < 1 || p > 65535 {
				return errors.New("usage: porthub http.server stop PORT|--all")
			}
			port = p
		}
		stopped, err := fileserver.Stop(port)
		for _, r := range stopped {
			fmt.Printf("Stopped http.server on port %d (pid %d)\n", r.Port, r.PID)
		}
		legacyStopped := 0
		for _, l := range fileserver.FindLegacy() {
			if port == 0 || l.Port == port {
				if e := fileserver.StopLegacy(l); e == nil {
					fmt.Printf("Stopped legacy lighttpd http.server on port %d (pid %d)\n", l.Port, l.PID)
					legacyStopped++
				}
			}
		}
		if err != nil && legacyStopped > 0 && len(stopped) == 0 && port != 0 {
			return nil
		}
		if err == nil && port == 0 && len(stopped)+legacyStopped == 0 {
			fmt.Println("No porthub http.server is running for this user")
		}
		return err
	}
	o := fileserver.Options{Port: 8000, Bind: "0.0.0.0", Path: "."}
	var positional []string
	value := func(i *int, name string) (string, error) {
		if k, v, ok := strings.Cut(args[*i], "="); ok && strings.HasPrefix(k, "--") {
			return v, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("missing value for %s", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		var err error
		var v string
		switch {
		case a == "-h" || a == "--help":
			fmt.Println(usage)
			return nil
		case a == "-p" || a == "--port" || strings.HasPrefix(a, "--port="):
			if v, err = value(&i, "--port"); err == nil {
				o.Port, err = strconv.Atoi(v)
			}
		case a == "--path" || strings.HasPrefix(a, "--path="):
			o.Path, err = value(&i, "--path")
		case a == "--bind" || strings.HasPrefix(a, "--bind="):
			o.Bind, err = value(&i, "--bind")
		case a == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown http.server option: %s", a)
		default:
			positional = append(positional, a)
		}
		if err != nil {
			return err
		}
	}
	switch len(positional) {
	case 0:
	case 1:
		if p, err := strconv.Atoi(positional[0]); err == nil {
			o.Port = p
		} else {
			o.Path = positional[0]
		}
	case 2:
		p, err := strconv.Atoi(positional[0])
		if err != nil {
			return errors.New("usage: porthub http.server [port] [path]")
		}
		o.Port, o.Path = p, positional[1]
	default:
		return errors.New("usage: porthub http.server [port] [path]")
	}
	return fileserver.Serve(ctx, o)
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New(usage)
	}
	// SIGHUP (terminal closed) also shuts down cleanly; lighttpd treated it as
	// "reopen logs" and kept holding its port after the terminal was gone.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	switch os.Args[1] {
	// Drop-in for the rathole client binary the shell client used to run
	// ("rathole -c client.toml", "rathole -V").
	case "-c", "--client":
		if len(os.Args) != 3 {
			return errors.New("usage: porthub -c client.toml")
		}
		return tunnel.RunFile(ctx, os.Args[2])
	case "-V":
		fmt.Println("porthub " + version)
		return nil
	case "http.server", "http-server":
		return httpServer(ctx, os.Args[2:])
	case "service":
		// Boot-time service for the private-network agent.
		if len(os.Args) < 3 {
			return errors.New("usage: porthub service install --profile FILE | uninstall [--purge] | status")
		}
		switch os.Args[2] {
		case "install":
			flags := flag.NewFlagSet("service install", flag.ContinueOnError)
			profile := flags.String("profile", "", "enrolled private profile")
			if err := flags.Parse(os.Args[3:]); err != nil {
				return err
			}
			if *profile == "" {
				return errors.New("--profile is required")
			}
			if _, err := agent.ReadConfig(*profile); err != nil {
				return err
			}
			if err := service.Install(*profile); err != nil {
				return err
			}
			fmt.Printf("Installed and started %s; it starts at boot and restarts if it exits.\n", service.Unit)
			return nil
		case "uninstall":
			purge := len(os.Args) > 3 && os.Args[3] == "--purge"
			if err := service.Uninstall(purge); err != nil {
				return err
			}
			fmt.Printf("Removed %s.\n", service.Unit)
			return nil
		case "status":
			active, enabled, err := service.Status()
			if err != nil {
				return err
			}
			fmt.Printf("%s: %s (boot: %s)\n", service.Unit, active, enabled)
			return nil
		}
		return errors.New("usage: porthub service install --profile FILE | uninstall [--purge] | status")
	case "supervise":
		// PID 1 of the single server container (see Dockerfile at repo root).
		flags := flag.NewFlagSet("supervise", flag.ContinueOnError)
		procfile := flags.String("procfile", "/etc/porthub/Procfile", "processes to run")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		f, err := os.Open(*procfile)
		if err != nil {
			return err
		}
		procs, err := supervise.Parse(f)
		f.Close()
		if err != nil {
			return err
		}
		return supervise.Run(ctx, procs, 20*time.Second)
	case "relay-server":
		// Gateway side of the private-network relay; reached through the
		// PortHub web address (see internal/relay). Secret from the env only.
		flags := flag.NewFlagSet("relay-server", flag.ContinueOnError)
		listen := flags.String("listen", "127.0.0.1:8091", "HTTP listen address for the relay WebSocket")
		maxConnections := flags.Int("max-connections", 1024, "concurrent relay connections")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		server, err := relay.NewServer(os.Getenv("PORTHUB_RELAY_SECRET"), *maxConnections)
		if err != nil {
			return err
		}
		defer server.Close()
		httpServer := &http.Server{Addr: *listen, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { <-ctx.Done(); _ = httpServer.Close() }()
		log.Printf("private relay listening on %s%s", *listen, relay.Path)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case "tunnel":
		flags := flag.NewFlagSet("tunnel", flag.ContinueOnError)
		config := flags.String("config", "", "rathole-format client TOML")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *config == "" && flags.NArg() == 1 {
			*config = flags.Arg(0)
		}
		if *config == "" {
			return errors.New("usage: porthub tunnel --config client.toml")
		}
		return tunnel.RunFile(ctx, *config)
	case "get":
		if len(os.Args) != 3 {
			return errors.New("usage: porthub get <http(s)-url>")
		}
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		path, err := download.Get(ctx, download.Options{URL: os.Args[2], Dir: dir, Progress: os.Stderr})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[porthub-get] Saved %s\n", path)
		return nil
	case "version":
		fmt.Println(version)
		return nil
	case "run":
		flags := flag.NewFlagSet("run", flag.ContinueOnError)
		profile := flags.String("profile", "", "private profile file")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		c, err := agent.ReadConfig(*profile)
		if err != nil {
			return err
		}
		runtime, err := agent.New(c)
		if err != nil {
			return err
		}
		return runtime.Run(ctx)
	case "enroll":
		flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
		server := flags.String("server", "", "HTTPS PortHub URL")
		profile := flags.String("profile", "", "new private profile file")
		insecure := flags.Bool("allow-insecure-http-for-tests", false, "isolated test networks only")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *profile == "" {
			return errors.New("--profile is required")
		}
		if _, err := os.Lstat(*profile); !os.IsNotExist(err) {
			return errors.New("profile already exists or cannot be checked; refusing to overwrite it")
		}
		fmt.Fprintln(os.Stderr, "Read a single-use installer ticket from stdin (not command-line arguments):")
		ticket, err := io.ReadAll(io.LimitReader(os.Stdin, 201))
		if err != nil {
			return err
		}
		if n := len(strings.TrimSpace(string(ticket))); n < 32 || n > 200 {
			return errors.New("invalid installer ticket")
		}
		c, err := agent.Bootstrap(ctx, *server, strings.TrimSpace(string(ticket)), *insecure)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*profile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = json.NewEncoder(f).Encode(c); err != nil {
			f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Private profile enrolled; existing public client configuration is unchanged.")
		return nil
	default:
		return errors.New("unknown command")
	}
}
