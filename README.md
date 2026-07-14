# URL-Unmasker: Safe HTTP/HTTPS Redirect Inspector

A lightweight, production-ready C++17 command-line tool for safely revealing where shortened or masked links actually lead — without executing payloads or trusting intermediaries.

**Perfect for:** Security analysts, penetration testers, SOC teams, and security-conscious users investigating suspicious links.

---

## ✨ Key Features

- **💧 Safe by design** — Uses HTTP HEAD requests only (no body download, minimal network footprint)
- **🔗 Redirect chain tracing** — Follows HTTP/HTTPS 3xx redirects up to 15 hops
- **🌐 DNS resolution** — Shows resolved IP address for each redirect
- **🚫 SSRF Protection** — Blocks redirects to private IPs (127/8, 10/8, 172.16-31/12, 192.168/16, link-local, IPv6 loopback)
- **✅ Protocol validation** — Only allows HTTP/HTTPS schemes (no file://, gopher://, etc.)
- **🛡️ CRLF injection prevention** — Sanitizes malformed Location headers
- **⚡ Production-ready** — Full error handling, verbose logging, configurable timeouts
- **📦 Minimal dependencies** — POSIX sockets + OpenSSL (optional TLS verification)

---

## 🚀 Quick Start

### Compile

```bash
# HTTPS support (recommended)
g++ -std=c++17 -Wall -Wextra -O3 unmask.cpp -o unmask -lssl -lcrypto

# HTTP-only (minimal)
g++ -std=c++17 -Wall -Wextra -O3 unmask.cpp -o unmask
```

### Run

```bash
./unmask https://bit.ly/example
./unmask https://tinyurl.com/abc123 https://t.co/xyz789
./unmask --help
```

---

## 📋 Usage

```
Usage: unmask <url1> [url2 ...]

Examples:
  unmask https://bit.ly/example
  unmask https://t.co/abc123 https://short.link/xyz

Features:
  - Follows 3xx redirects to final destination
  - Resolves IP addresses for each host
  - Blocks SSRF attacks (private IP filtering)
  - Shows complete redirect chain with status codes
  - Supports HTTP and HTTPS only
```

---

## 📤 Output Examples

### Example 1: Simple Redirect

```bash
$ ./unmask https://bit.ly/example
```

```
[Source]      https://bit.ly/example
[Resolved IP] 157.173.201.23
[Final URL]   https://vignettinglife.com/
[Hops]
  1) 301 -> http://vignettinglife.com/ [67.199.248.11]
     next: http://vignettinglife.com/
  2) 301 -> https://vignettinglife.com/ [157.173.201.23]
     next: https://vignettinglife.com/
  3) 200 [157.173.201.23]
```

### Example 2: SSRF Blocked

```bash
$ ./unmask https://attacker.com/metadata
[BLOCKED] SSRF to 169.254.169.254
[ERROR] Connect failed
```

### Example 3: Protocol Validation

```bash
$ ./unmask https://attacker.com/payload
[BLOCKED] Non-HTTP: file:///etc/passwd
```

---

## 🔐 Security Features

### SSRF Protection
Blocks redirects to private IP ranges:
- **IPv4**: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
- **IPv6**: ::1, fc00::/7, fe80::/10, ::ffff:127.0.0.0/104

Prevents exploitation attempts like:
```
https://attacker.com/redir → 169.254.169.254 (AWS metadata)
https://attacker.com/redir → 192.168.1.1 (internal router)
https://attacker.com/redir → http://127.0.0.1:22 (SSH)
```

### Protocol Validation
Only allows `http://` and `https://` schemes. Blocks:
```
file:///etc/passwd
gopher://internal.network
dict://internal.service
ldap://dc.internal
```

### CRLF Injection Prevention
Sanitizes malformed Location headers:
```
Location: http://example.com\r\nX-Injected: true
→ Parsed as: http://example.com X-Injected: true (safe)
```

### Resource Safety
- **Timeouts**: 5-second socket timeouts prevent hanging
- **Max hops**: 15 redirects (prevents infinite loops)
- **Header limit**: 256 KB per response
- **Move semantics**: Prevents socket double-closes via RAII

---

## ⚙️ Configuration

Edit constants at the top of `unmask.cpp`:

```cpp
constexpr int SOCKET_TIMEOUT_SECS = 5;        // Connection timeout
constexpr size_t MAX_HEADER_SIZE = 256 * 1024; // Max header size
constexpr int MAX_REDIRECT_HOPS = 15;          // Max redirect chain length
```

### Enable TLS Certificate Verification (optional)

Change line 30:
```cpp
constexpr bool VERIFY_TLS = true;  // Default: false (accepts self-signed)
```

Recompile:
```bash
g++ -std=c++17 -Wall -Wextra -O3 unmask.cpp -o unmask -lssl -lcrypto
```

---

## 📊 Technical Details

### How It Works

1. **Parse URL** — Extract scheme, host, port, path via regex
2. **Resolve DNS** — Use `getaddrinfo()` to get IP addresses
3. **Filter SSRF** — Reject private IPs
4. **Send HEAD** — HTTP/1.1 HEAD request with Host and Connection headers
5. **Parse Response** — Extract status code and Location header
6. **Follow Redirect** — If 3xx, resolve relative URLs and repeat
7. **Report Chain** — Show hop-by-hop output with status codes and IPs

### RAII & Memory Safety

- **Socket RAII**: File descriptors auto-closed via destructor
- **TLS cleanup**: SSL/SSL_CTX freed on scope exit
- **Move semantics**: Prevents ownership confusion and double-closes
- **Unique pointers**: `std::unique_ptr` for auto cleanup

### Error Handling

All network failures are logged:
```
[ERROR] getaddrinfo: Name or service not known
[ERROR] Connect failed
[ERROR] TLS handshake
[ERROR] SSL_write
[BLOCKED] SSRF to 127.0.0.1
[BLOCKED] Non-HTTP: file:///etc/passwd
[WARN] Max redirects exceeded
```

---

## 📦 Compilation Requirements

| Component | Requirement | Optional |
|-----------|-------------|----------|
| Compiler | C++17 (g++ 7+, clang++ 5+) | ✓ |
| POSIX sockets | Linux/BSD/macOS default | ✗ |
| OpenSSL | libssl-dev, libcrypto | ✓ (HTTP only) |

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl-dev
```

**macOS:**
```bash
brew install openssl
```

**CentOS/RHEL:**
```bash
sudo yum install openssl-devel
```

---

## 🧪 Testing

```bash
# Compile
g++ -std=c++17 -Wall -Wextra -O3 unmask.cpp -o unmask -lssl -lcrypto

# Test 1: Normal redirect
./unmask https://bit.ly/example

# Test 2: Multiple URLs
./unmask https://bit.ly/1 https://bit.ly/2 https://bit.ly/3

# Test 3: SSRF blocking (if attacker.com redirects to private IP)
./unmask https://attacker.com/metadata

# Test 4: Help
./unmask --help
```

---

## 🎯 Use Cases

### Security & Incident Response
- Investigate suspicious shortened links in phishing emails
- Triage potentially malicious URLs without executing code
- Document redirect chains for forensic reports
- Test SSRF protections in web apps

### Threat Intelligence
- Track affiliate marketing redirects
- Monitor URL shortening service behavior
- Detect redirect chains used in attacks

### Security Awareness Training
- Show employees where clicks really go
- Demonstrate redirect-based phishing attacks
- Safe sandbox for malicious link analysis

### Penetration Testing
- Recon external targets via redirect chains
- Test for SSRF vulnerabilities
- Document full attack paths

---

## 🚨 Security Considerations

### What Unmasker Does NOT Do
- ❌ Execute JavaScript or download file content
- ❌ Render HTML or run plugins
- ❌ Follow WebSockets or custom protocols
- ❌ Bypass authentication or cookies

### Safe for Malicious Links?
✅ **Yes.** HEAD requests never download bodies, so:
- No script execution
- No exploit payloads triggered
- No drive-by downloads
- Minimal attack surface

Still, run untrusted URLs in **sandboxed environments** (VM, container).

---

## 📝 Output Format

Each URL produces:
```
[Source]      <input URL>
[Resolved IP] <final IP or unknown>
[Final URL]   <destination after all redirects>
[Hops]        (optional, if redirects exist)
  1) <status> -> <location> [<ip>]
     next: <resolved next URL>
  2) <status> [<ip>]
```

---

## 🔗 Related Tools

| Tool | Method | Pros | Cons |
|------|--------|------|------|
| **Unmasker** | C++17 CLI | Purpose-built, minimal deps, safe | CLI only |
| `curl -I` | libcurl | Full feature set | Larger attack surface |
| `wget --spider` | wget | Simple | Limited control |
| `python-requests` | Python | Scripting-friendly | Heavyweight |

---

## 📄 License

**MIT License** — Use freely in commercial & personal projects.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

See LICENSE file for full text.

---

## 🤝 Contributing

Contributions welcome! Please:

1. **Keep it minimal** — No heavy dependencies
2. **Test both HTTP & HTTPS** — Ensure compatibility
3. **Maintain security** — No TLS verification bypass
4. **Add tests** — Include example URLs or test cases
5. **Document changes** — Update this README

### Areas for Contribution
- JSON output format
- WHOIS lookups per hop
- Proxy support (SOCKS5 / HTTP)
- Timeout flags
- Rate limiting
- IPv6 improvements

---

## ⚡ Performance

- **Single URL**: ~100-500ms (depends on network latency)
- **10 URLs**: ~1-5s
- **Memory**: <10MB typical
- **CPU**: Minimal (I/O bound)

---

## 🐛 Known Limitations

- Max 15 redirects (prevent infinite loops)
- Max 256 KB headers per response
- No proxy support (yet)
- No cookie/session support (HEAD only)

---

## 📞 Support

Found a bug? Have a feature request?

1. Test with a known shortlink first
2. Check error messages for details
3. Run with `./unmask --help`
4. Open an issue with steps to reproduce

---

## 🎓 Learning Resources

- [HTTP/1.1 Redirects (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections)
- [SSRF Attacks (OWASP)](https://owasp.org/www-community/attacks/Server-Side_Request_Forgery)
- [C++17 Features](https://en.cppreference.com/w/cpp/17)

---

**Built with security & simplicity in mind.** 🔒

