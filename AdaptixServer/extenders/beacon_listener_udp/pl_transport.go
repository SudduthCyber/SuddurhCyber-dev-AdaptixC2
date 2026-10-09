package main

import (
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Listener struct {
	transport *TransportUDP
}

type TransportUDP struct {
	Conn   *net.UDPConn
	Config TransportConfig
	Name   string
	Active bool

	stopCh   chan struct{}
	clientMu sync.Mutex
	clients  map[string]*net.UDPAddr
}

type TransportConfig struct {
	HostBind           string   `json:"host_bind"`
	PortBind           int      `json:"port_bind"`
	Callback_addresses []string `json:"callback_addresses"`
	EncryptKey         string   `json:"encrypt_key"`
	MaxPacketSize      int      `json:"max_packet_size"`

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

	if conf.MaxPacketSize != 0 && (conf.MaxPacketSize < 512 || conf.MaxPacketSize > 65507) {
		return errors.New("max_packet_size must be between 512 and 65507")
	}

	return nil
}

func (t *TransportUDP) Start(ts Teamserver) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", t.Config.HostBind, t.Config.PortBind))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}

	t.Conn = conn
	t.Active = true
	t.stopCh = make(chan struct{})
	t.clients = make(map[string]*net.UDPAddr)

	maxPacket := t.Config.MaxPacketSize
	if maxPacket == 0 {
		maxPacket = 65507
	}

	fmt.Printf("   Started listener '%s': udp://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

	go t.readLoop(ts, maxPacket)

	return nil
}

func (t *TransportUDP) Stop() error {
	t.Active = false
	close(t.stopCh)
	if t.Conn != nil {
		return t.Conn.Close()
	}
	return nil
}

func (t *TransportUDP) readLoop(ts Teamserver, maxPacket int) {
	buf := make([]byte, maxPacket)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		n, remoteAddr, err := t.Conn.ReadFromUDP(buf)
		if err != nil {
			if !t.Active {
				return
			}
			continue
		}

		if n < 8 {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go t.handlePacket(data, remoteAddr, ts)
	}
}

func (t *TransportUDP) handlePacket(data []byte, remoteAddr *net.UDPAddr, ts Teamserver) {
	externalIP := remoteAddr.IP.String()

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

	t.clientMu.Lock()
	t.clients[agentId] = remoteAddr
	t.clientMu.Unlock()

	responseData, err := ts.TsAgentGetHostedAll(agentId, 0xFE00) // ~64KB max for UDP
	if err != nil {
		return
	}

	if len(responseData) > 0 {
		_, _ = t.Conn.WriteToUDP(responseData, remoteAddr)
	}
}

func (t *TransportUDP) parseBeatAndData(data []byte) (string, string, []byte, []byte, error) {
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
