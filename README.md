# 🔍 Unmasker — Safe HTTP/HTTPS Redirect Inspector

* **Unmasker** is a lightweight, open-source C++17 command-line tool for **safely revealing where a link really goes** — without ever executing the link’s payload.  
* It performs **HEAD** requests only (no content fetched), follows redirect chains, resolves DNS → IP, and outputs the final landing URL.

Perfect for **security analysts, penetration testers, or anyone dealing with potentially malicious shortlinks**.

---

## ✨ Features

- **Safe by design** — HEAD requests only (headers, never body)
- **Redirect chain tracing** — follow HTTP & HTTPS `3xx` responses up to 15 hops
- **DNS resolution** — shows resolved IP for each hop
- **Full control** — optional TLS certificate verification
- **Open-source & dependency-light** — only requires:
  - POSIX sockets (HTTP)
  - OpenSSL (for HTTPS)

---

## 📥 Installation

### Requirements
- Linux, macOS, or BSD with a C++17 compiler
- `g++` or `clang++`
- `libssl` / `libcrypto` (for HTTPS mode)

---

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/unmasker.git
cd unmasker
```

---

### 2. Compile

#### HTTP-only build (no TLS, minimal dependencies)
```bash
g++ -std=gnu++17 -O2 -Wall -Wextra -pedantic unmask.cpp -o unmask
```

> Use this if you **only** care about `http://` URLs and want a completely dependency-free build.

#### HTTP + HTTPS build (OpenSSL TLS support)
```bash
g++ -std=gnu++17 -O2 -Wall -Wextra -pedantic unmask.cpp -o unmask -lssl -lcrypto
```

> Use this if you want to **fully follow** shortlinks and redirects that go through `https://`.

#### Enable TLS certificate verification
```bash
g++ -std=gnu++17 -O2 -Wall -Wextra -pedantic -DVERIFY_TLS=1 unmask.cpp -o unmask -lssl -lcrypto
```

> By default, TLS certificate verification is **disabled** to avoid breaking resolution for malicious or self-signed hosts.

---

## 🖥 Usage

Basic syntax:
```bash
./unmask <url1> [url2 ...]
```

Example:
```bash
./unmask https://tinyurl.com/mrx6hse5
```

Output:
```
[Source] https://tinyurl.com/mrx6hse5
[Resolved IP] 104.17.112.233
[Final URL] https://example.org/real-page
[Hops]
  1) 301 -> https://www.example.com/page [ip:93.184.216.34]
     next: https://www.example.com/page
  2) 302 -> https://example.org/real-page [ip:93.184.216.34]
     next: https://example.org/real-page
```

---

## 🔐 Safety Notes

- **Unmasker never executes scripts or downloads file content** — only retrieves headers.
- Because it uses **HEAD requests**, it’s ideal for inspecting **potentially malicious links** without risking system compromise.
- Forensic analysts can log and document redirect chains without triggering malicious payloads.

---

## ⚙ Options & Behavior

- **Max hops**: 15 (configurable in code)
- **Output format**: Always shows `[Source]`, `[Resolved IP]`, `[Final URL]`, and an optional hop list.
- **Relative redirects**: Correctly resolved against the base URL.
- **Loop detection**: Prevents infinite redirect loops.

---

## 📜 Example Use Cases

- Investigating suspicious email shortlinks (`bit.ly`, `tinyurl`, `t.co`, etc.)
- Security awareness training for end-users
- Recon in penetration tests where link targets need verification
- Tracking affiliate marketing redirects without clicking them
- OSINT research into link tracking behavior

---

## 🛠 Roadmap

- [ ] JSON output mode for easy scripting integration
- [ ] Optional per-hop WHOIS lookups
- [ ] SOCKS5 / HTTP proxy support
- [ ] Timeout control via CLI flags

---

## 📄 License

MIT License — feel free to fork, modify, and use in your own projects.

---

## 🙌 Contributing

PRs are welcome! Please:
1. Keep code dependency-light.
2. Ensure any TLS-related changes remain safe for malicious-link inspection.
3. Test both HTTP and HTTPS modes.

---

## 🔗 Related Tools

- [`curl -I`](https://curl.se/) — similar functionality but executes through full libcurl stack.
- [`wget --spider`](https://www.gnu.org/software/wget/) — header-only fetching for single URLs.
- **Unmasker** — purpose-built for security, with controlled redirect following and minimal attack surface.

