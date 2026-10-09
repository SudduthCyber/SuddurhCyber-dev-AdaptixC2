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
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

type Listener struct {
	transport *TransportQUIC
}

type TransportQUIC struct {
	QListener *quic.Listener
	Config    TransportConfig
	Name      string
	Active    bool

	cancelCtx context.Context
	cancelFn  context.CancelFunc
}

type TransportConfig struct {
	HostBind           string   `json:"host_bind"`
	PortBind           int      `json:"port_bind"`
	Callback_addresses []string `json:"callback_addresses"`
	EncryptKey         string   `json:"encrypt_key"`

	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

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

	match, _ := regexp.MatchString("^[0-9a-f]{32}$", conf.EncryptKey)
	if len(conf.EncryptKey) != 32 || !match {
		return errors.New("encrypt_key must be 32 hex characters")
	}

	return nil
}

func (t *TransportQUIC) Start(ts Teamserver) error {
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
			return err
		}
	} else {
		err = os.WriteFile(t.Config.SslCertPath, t.Config.SslCert, 0600)
		if err != nil {
			return err
		}
		err = os.WriteFile(t.Config.SslKeyPath, t.Config.SslKey, 0600)
		if err != nil {
			return err
		}
	}

	cert, err := tls.LoadX509KeyPair(t.Config.SslCertPath, t.Config.SslKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"adaptix-quic"},
		MinVersion:   tls.VersionTLS13,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", t.Config.HostBind, t.Config.PortBind)
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %v", err)
	}

	t.QListener = listener
	t.Active = true

	t.cancelCtx, t.cancelFn = context.WithCancel(context.Background())

	fmt.Printf("   Started listener '%s': quic://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

	go t.acceptLoop(ts)

	time.Sleep(500 * time.Millisecond)
	return nil
}

func (t *TransportQUIC) Stop() error {
	t.Active = false
	if t.cancelFn != nil {
		t.cancelFn()
	}

	listenerPath := ListenerDataDir + "/" + t.Name
	_, err := os.Stat(listenerPath)
	if err == nil {
		_ = os.RemoveAll(listenerPath)
	}

	if t.QListener != nil {
		return t.QListener.Close()
	}
	return nil
}

func (t *TransportQUIC) acceptLoop(ts Teamserver) {
	for {
		conn, err := t.QListener.Accept(t.cancelCtx)
		if err != nil {
			if t.cancelCtx.Err() != nil {
				return
			}
			continue
		}

		go t.handleConnection(conn, ts)
	}
}

func (t *TransportQUIC) handleConnection(conn *quic.Conn, ts Teamserver) {
	defer conn.CloseWithError(0, "done")

	ExternalIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(ExternalIP); err == nil {
		ExternalIP = host
	}

	for {
		stream, err := conn.AcceptStream(t.cancelCtx)
		if err != nil {
			return
		}

		go t.handleStream(stream, ts, ExternalIP)
	}
}

func (t *TransportQUIC) handleStream(stream *quic.Stream, ts Teamserver, externalIP string) {
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil || len(data) < 8 {
		return
	}

	agentType, agentId, beat, bodyData, err := t.parseBeatAndData(data)
	if err != nil {
		return
	}

	if !ts.TsAgentIsExists(agentId) {
		_, err = ts.TsAgentCreate(agentType, agentId, beat, t.Name, externalIP, true)
		if err != nil {
			return
		}
	}

	_ = ts.TsAgentSetTick(agentId, t.Name)
	_ = ts.TsAgentProcessData(agentId, bodyData)

	responseData, err := ts.TsAgentGetHostedAll(agentId, 0x1900000)
	if err != nil {
		return
	}

	_, _ = stream.Write(responseData)
}

func (t *TransportQUIC) parseBeatAndData(data []byte) (string, string, []byte, []byte, error) {
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

func (t *TransportQUIC) generateSelfSignedCert(certFile, keyFile string) error {
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
