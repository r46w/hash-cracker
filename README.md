# 🔓 hashcrack

> hash cracker written in C — wordlist & brute force

**supported hashes:** `md5` · `sha1` · `sha256` · `sha512` · `ntlm`

---

## ⚙️ build

```bash
gcc -O2 -o hashcrack hashcrack.c -lssl -lcrypto
```

> 📦 requires openssl — `apt install libssl-dev`

---

## 🚀 usage

**📋 wordlist attack**
```bash
./hashcrack -h 5f4dcc3b5aa765d61d8327deb882cf99 -w /usr/share/wordlists/rockyou.txt
```

**💪 brute force**
```bash
./hashcrack -h 5f4dcc3b5aa765d61d8327deb882cf99 -b -c abcdefghijklmnopqrstuvwxyz0123456789 -l 6
```

**🎯 specify hash type manually**
```bash
./hashcrack -h <hash> -t sha256 -w wordlist.txt
```

**⚡ both methods combined**
```bash
./hashcrack -h <hash> -w rockyou.txt -b -l 4
```

---

## 🛠️ options

| flag | description |
|------|-------------|
| `-h` | hash to crack |
| `-t` | type: `md5` `sha1` `sha256` `sha512` `ntlm` (auto-detect if omitted) |
| `-w` | wordlist path |
| `-b` | enable brute force |
| `-c` | charset for brute force (default: `a-z0-9`) |
| `-l` | max length for brute force (default: `6`) |

---

> ⚠️ *for educational purposes only*
