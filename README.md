# Python Source Code Scanner

A static analysis tool, written in Rust, that scans Python source trees for common
security vulnerabilities.

### Detects

43 rules across 18 categories, tuned to skip the safe form of an API (parameterized
SQL, list-form `subprocess` calls, hardcoded literal file paths) so results stay
signal over noise:

| Category | Examples |
|---|---|
| Command Injection | `os.system`, `os.popen`, `subprocess(... shell=True)` |
| Code Injection | `eval`, `exec` |
| Insecure Deserialization | `pickle.load(s)`, `yaml.load`, `marshal.loads` |
| SQL Injection | f-string / `%`-format / `.format()` / concatenation passed to `.execute()` (parameterized queries are not flagged) |
| Cross-Site Scripting (Django) | `mark_safe`, `SafeText`/`SafeString`, `autoescape=False` |
| Server-Side Template Injection (SSTI) | `render_template_string(f"...")` |
| Path Traversal | `open(`/`os.path.join(`/`Path(` built from request data, `input()`, `sys.argv`, `os.environ`, an f-string, or concatenation |
| Weak Cryptography | `hashlib.md5`, `hashlib.sha1`, `random` used where `secrets` is needed |
| Hardcoded Secrets | variable-name heuristics (`password =`, `DB_PASSWORD =`, `STRIPE_API_KEY =`, ...) plus value-pattern matches for AWS keys, PEM private key blocks, Slack tokens, GitHub tokens, and JWTs |
| XXE | `xml.etree.ElementTree`, `lxml.etree` parsing without hardening |
| SSRF | `requests.get/post/...` called with a dynamically built URL |
| Insecure Temp Files | `tempfile.mktemp()` |
| Insecure Configuration | Django `DEBUG=True`, Flask `debug=True`, binding to `0.0.0.0` |
| Insecure TLS Configuration | `requests.get(..., verify=False)`, `ssl.CERT_NONE`, `ssl._create_unverified_context()` |
| CORS | wildcard `origins: "*"` |
| Insecure Cookie | `set_cookie(..., secure=False)` / `httponly=False` |
| Open Redirect | `redirect(request.args...)` |
| Insecure File Permissions | `os.chmod(path, 0o777)` |
| Insecure JWT Handling | `jwt.decode(..., verify=False)`, `algorithms=["none"]` |

Each finding is tagged with a severity (`INFO` → `CRITICAL`) and sorted most severe
first. Directories that are never useful to scan (`.git`, virtualenvs, `__pycache__`,
`node_modules`, etc.) are skipped automatically.

### Download

```
$ git clone https://github.com/MorphyKutay/Py-Source-Code-Scanner.git

$ cd Py-Source-Code-Scanner

$ cargo build

```

**OR (Windows)**
```

$ wget https://github.com/MorphyKutay/Py-Source-Code-Scanner/releases/download/1.0/main.exe

$ ./main.exe --help

```

**OR (Linux)**
```

$ wget https://github.com/MorphyKutay/Py-Source-Code-Scanner/releases/download/1.0/main

$ ./main --help

```

### Usage

```
$ ./main --path ./my_project

$ ./main --path ./my_project --format json --output findings.json

$ ./main --path ./my_project --no-color --no-banner
```

| Flag | Description |
|---|---|
| `-p, --path <PATH>` | File or directory to scan (required) |
| `-o, --output <FILE>` | Write findings to a file (text or JSON, based on `--format`) |
| `-f, --format <text\|json>` | Output format for stdout and `--output` (default: `text`) |
| `--no-banner` | Suppress the startup banner |
| `--no-color` | Disable ANSI colors in text output |

The exit code is non-zero if any `HIGH` or `CRITICAL` finding is reported, so the
scanner can be used as a CI gate.

### Testing

```
$ cargo test
```

![alt text](https://github.com/MorphyKutay/Py-Source-Code-Scanner/blob/main/ss1.png)
