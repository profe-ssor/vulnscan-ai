from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

# ---------------------------------------------------------------------------
# Config -- aligned with team starter files
# ---------------------------------------------------------------------------

DB_DIR = "./chroma_cve_db"             # matches 2_embed_to_chroma.py
COLLECTION_NAME = "cve_collection"     # matches 2_embed_to_chroma.py
RAW_DATA_DIR = "./raw_knowledgebase"   # output of 1_download_raw_cves.py
EMBEDDING_MODEL_NAME = "BAAI/bge-large-en-v1.5"
EMBEDDING_DEVICE = "cpu"

CHUNK_SIZE = 400
CHUNK_OVERLAP = 80

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def _get_db() -> Chroma:
    """Shared LangChain Chroma handle -- same config as 2_embed_to_chroma.py."""
    log.info("Loading embedding model %s ...", EMBEDDING_MODEL_NAME)
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_NAME,
        model_kwargs={"device": EMBEDDING_DEVICE},
        encode_kwargs={"normalize_embeddings": True},
    )
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=embeddings,
        persist_directory=DB_DIR,
    )


# ---------------------------------------------------------------------------
# OWASP Top 10 (2025)
# What changed vs 2021:
#   - A03 is now "Software Supply Chain Failures" (was Injection)
#   - Injection moved to A05 (was A03)
#   - Security Misconfiguration moved to A02 (was A05)
#   - Cryptographic Failures moved to A04 (was A02)
#   - Logging renamed to "Logging & Alerting Failures"
#   - Auth renamed to "Authentication Failures"
#   - A10 is now "Mishandling of Exceptional Conditions" (SSRF dropped)
# ---------------------------------------------------------------------------

OWASP_TOP_10: list[dict[str, Any]] = [
    {
        "id": "A01:2025",
        "title": "Broken Access Control",
        "cwe_ids": ["CWE-200", "CWE-201", "CWE-284", "CWE-285", "CWE-352", "CWE-639"],
        "description": (
            "Access control enforces policy such that users cannot act outside of their "
            "intended permissions. Failures lead to unauthorized information disclosure, "
            "modification or destruction of data, or business functions outside the user's "
            "limits. Common issues: violation of least privilege, IDOR (insecure direct object "
            "references), missing access controls on POST/PUT/DELETE, privilege escalation, "
            "JWT metadata tampering, CORS misconfiguration, and force browsing to protected pages."
        ),
        "examples": (
            "Example 1 -- IDOR: pstmt.setString(1, request.getParameter('acct')) lets an "
            "attacker modify 'acct' to access any account number. "
            "Example 2 -- Force browsing: GET /admin/deleteUser succeeds without authentication "
            "because the route lacks an authorization check."
        ),
        "prevention": (
            "Deny by default. Enforce ownership checks server-side rather than trusting "
            "user-supplied IDs. Log access control failures and alert on repeated failures. "
            "Rate limit API endpoints. Disable web server directory listing. Re-use a single "
            "centralized access control mechanism throughout the application."
        ),
    },
    {
        "id": "A02:2025",
        "title": "Security Misconfiguration",
        "cwe_ids": ["CWE-16", "CWE-611", "CWE-209", "CWE-732"],
        "description": (
            "Security misconfiguration is the most common finding. Causes include: missing "
            "security hardening across the stack, open cloud storage buckets, unnecessary "
            "features or services enabled, default accounts unchanged, overly informative "
            "error messages revealing stack traces or internal paths, XXE injection enabled "
            "in XML parsers, outdated software with known CVEs, and security settings left "
            "at insecure default values in frameworks, databases, or servers."
        ),
        "examples": (
            "Example 1 -- Default admin console: Application server admin console installed "
            "and not removed. Default credentials allow attacker to take over. "
            "Example 2 -- Directory listing enabled: Attacker browses file structure, downloads "
            "compiled Java classes, reverse-engineers authentication logic. "
            "Example 3 -- Verbose errors: Stack traces expose class names, file paths, "
            "framework versions, and internal logic to attackers."
        ),
        "prevention": (
            "Repeatable hardening processes. Identical Dev/QA/Prod configs with different "
            "credentials. Minimal platform: disable all unused features, components, and docs. "
            "Automated scanning of config settings in CI/CD pipelines. Segmented architecture. "
            "Send security directives to clients via headers (CSP, HSTS, X-Content-Type)."
        ),
    },
    {
        "id": "A03:2025",
        "title": "Software Supply Chain Failures",
        "cwe_ids": ["CWE-1035", "CWE-829", "CWE-494", "CWE-937"],
        "description": (
            "NEW in 2025. Software supply chain failures occur when third-party libraries, "
            "packages, container images, or build tools are compromised, outdated, or "
            "tampered with. This includes: using dependencies with known CVEs, typosquatting "
            "attacks (malicious packages with names similar to popular ones), compromised "
            "npm/PyPI packages, malicious CI/CD pipeline steps, unverified container base "
            "images, and transitive dependency vulnerabilities. Replaces the 2021 category "
            "'Vulnerable and Outdated Components' with a broader supply chain focus."
        ),
        "examples": (
            "Example 1 -- Known CVE dependency: Application uses log4j 2.14.1, vulnerable to "
            "Log4Shell (CVE-2021-44228), allowing remote code execution via JNDI lookup. "
            "Example 2 -- Typosquatting: Developer installs 'colourama' instead of 'colorama'; "
            "the malicious package exfiltrates environment variables. "
            "Example 3 -- Compromised build step: A GitHub Action is updated by an attacker "
            "who adds secret-exfiltration code to the action's entrypoint."
        ),
        "prevention": (
            "Maintain a software bill of materials (SBOM). Pin dependency versions and use "
            "lockfiles. Use Dependabot, Renovate, or OWASP Dependency-Check for automated "
            "CVE alerts. Verify package checksums/signatures. Prefer packages with active "
            "maintainers and high download counts from official registries. Scan container "
            "images. Restrict CI/CD pipeline permissions with least privilege."
        ),
    },
    {
        "id": "A04:2025",
        "title": "Cryptographic Failures",
        "cwe_ids": ["CWE-259", "CWE-327", "CWE-331", "CWE-326"],
        "description": (
            "Failures related to cryptography that lead to sensitive data exposure or system "
            "compromise. Data in transit or at rest is not encrypted; weak or deprecated "
            "algorithms (MD5, SHA-1, DES) are used; encryption keys are hardcoded, reused, "
            "or never rotated; IVs are not randomized for CBC mode; non-authenticated "
            "encryption is used; passwords are stored using fast hashing algorithms "
            "instead of bcrypt/argon2/scrypt."
        ),
        "examples": (
            "Example 1 -- Unsalted MD5: Database stores password hashes with MD5 without salt. "
            "All hashes cracked instantly via rainbow tables after a breach. "
            "Example 2 -- Transparent DB encryption: Credit card numbers encrypted at rest "
            "but decrypted automatically on query, so SQL injection returns plaintext card numbers."
        ),
        "prevention": (
            "Classify sensitive data and do not store it unnecessarily. Encrypt all sensitive "
            "data at rest and in transit. Use strong, modern algorithms and protocols (AES-256, "
            "TLS 1.2+, SHA-256+). Use bcrypt, scrypt, or Argon2 for password storage. "
            "Never use ECB mode. Use authenticated encryption (AES-GCM). Disable caching "
            "for responses containing sensitive data. Enforce HTTPS."
        ),
    },
    {
        "id": "A05:2025",
        "title": "Injection",
        "cwe_ids": ["CWE-89", "CWE-77", "CWE-78", "CWE-79", "CWE-917"],
        "description": (
            "Injection flaws occur when untrusted data is sent to an interpreter as part of "
            "a command or query. SQL, NoSQL, OS command, LDAP, and XSS injection all apply. "
            "The application is vulnerable when: user-supplied data is not validated or "
            "sanitized; dynamic queries use string concatenation with user input; hostile data "
            "is used in ORM search parameters without escaping; eval() or exec() is called "
            "with user-controlled input."
        ),
        "examples": (
            "Example 1 -- SQL injection: query = 'SELECT * FROM accounts WHERE id=' + userId "
            "Attacker supplies: 1 OR 1=1 -- to return all rows. "
            "Example 2 -- Command injection: os.system('ls ' + userInput) where userInput "
            "is '; cat /etc/passwd' leaks the password file. "
            "Example 3 -- XSS: response.write(request.getParameter('name')) without escaping "
            "allows script injection into the HTML response."
        ),
        "prevention": (
            "Prefer a safe API with parameterized interfaces or ORMs. "
            "Use positive/allowlist server-side input validation. "
            "Escape special characters using the specific syntax for the target interpreter. "
            "Use LIMIT and other SQL controls to prevent mass data disclosure. "
            "Never call eval() or exec() with user-controlled strings."
        ),
    },
    {
        "id": "A06:2025",
        "title": "Insecure Design",
        "cwe_ids": ["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-256"],
        "description": (
            "Insecure design represents missing or ineffective security control design -- "
            "flaws that cannot be fixed by a perfect implementation alone because the "
            "necessary security controls were never designed in. Issues include: missing "
            "threat modeling during design, trust boundary violations, no business logic "
            "rate limiting, unenforced workflows (e.g. multi-step checkout bypass), "
            "and security requirements not captured as user stories."
        ),
        "examples": (
            "Example 1 -- Weak credential recovery: App uses security questions prohibited "
            "under NIST 800-63b, allowing account takeover via publicly available information. "
            "Example 2 -- No business logic limits: Cinema booking system allows reserving "
            "600 seats across all locations in one request with no cap, enabling revenue attacks."
        ),
        "prevention": (
            "Embed security into the SDLC with threat modeling for critical flows. "
            "Use secure design patterns and reference architectures. "
            "Write user stories that include security requirements and misuse cases. "
            "Integrate unit and integration tests that validate critical security controls. "
            "Limit resource consumption per user or service."
        ),
    },
    {
        "id": "A07:2025",
        "title": "Authentication Failures",
        "cwe_ids": ["CWE-287", "CWE-295", "CWE-297", "CWE-384", "CWE-620"],
        "description": (
            "Renamed from 'Identification and Authentication Failures' in 2021. "
            "Covers failures in confirming user identity and managing sessions. "
            "Vulnerabilities include: permitting weak passwords, lacking brute force "
            "protection, weak credential recovery via knowledge-based questions, "
            "plaintext or weakly hashed password storage, missing MFA, session IDs "
            "exposed in URLs, session IDs not rotated after login, sessions not invalidated "
            "on logout or after inactivity."
        ),
        "examples": (
            "Example 1 -- Credential stuffing: No brute force protection allows automated "
            "login attempts with a list of breached credentials. "
            "Example 2 -- Session fixation: Session token not rotated after login, allowing "
            "an attacker who set the pre-login token to hijack the authenticated session."
        ),
        "prevention": (
            "Implement MFA. Enforce strong password policies and check against breached "
            "password lists (HaveIBeenPwned API). Never ship default credentials. "
            "Use exponential backoff or lockout after failed login attempts. "
            "Server-side sessions with random, high-entropy IDs. Rotate session ID after login. "
            "Invalidate sessions on logout and after idle timeout."
        ),
    },
    {
        "id": "A08:2025",
        "title": "Software and Data Integrity Failures",
        "cwe_ids": ["CWE-502", "CWE-829", "CWE-915"],
        "description": (
            "Covers code and infrastructure that does not protect against integrity violations. "
            "Insecure deserialization of untrusted data, loading plugins from untrusted CDNs "
            "or registries, CI/CD pipeline without integrity checks, auto-update without "
            "signature verification, and client-side state stored in an insecure manner that "
            "an attacker can modify to change server-side behavior."
        ),
        "examples": (
            "Example 1 -- Insecure deserialization: pickle.loads(cookie_data) where the "
            "cookie is user-controlled achieves arbitrary code execution. "
            "Example 2 -- SolarWinds-style supply chain: Build pipeline CI step injected with "
            "malicious code that backdoors software updates for downstream customers."
        ),
        "prevention": (
            "Use digital signatures to verify software and data from expected sources. "
            "Ensure libraries are consumed from trusted registries. "
            "Use a dependency review process and SBOM. "
            "Do not serialize sensitive objects and send them to untrusted clients. "
            "Implement deserialization integrity checks or use safer formats (JSON + schema). "
            "Ensure CI/CD has proper access controls and integrity verification."
        ),
    },
    {
        "id": "A09:2025",
        "title": "Logging and Alerting Failures",
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "description": (
            "Renamed from 'Security Logging and Monitoring Failures' in 2021, with increased "
            "emphasis on alerting. Without adequate logging AND alerting, breaches go undetected. "
            "Problems include: login failures and high-value transactions not logged; logs stored "
            "only locally without centralization; no real-time alerting on anomalies; log "
            "injection vulnerabilities (CWE-117) from unvalidated log inputs; sensitive data "
            "written to log files; no defined incident response process."
        ),
        "examples": (
            "Example 1 -- No alerts: Attacker runs credential stuffing for weeks; no alert "
            "fires because login failure rate is not monitored. "
            "Example 2 -- Log injection: User supplies '\\n[ADMIN] Privilege granted' as their "
            "username; the string gets written to the log, spoofing an admin action. "
            "Example 3 -- Secrets in logs: logging.info(f'Connecting with password {db_pass}') "
            "exposes credentials in log files accessible to developers."
        ),
        "prevention": (
            "Log all authentication events, access control failures, and input validation errors "
            "with sufficient context (user, IP, timestamp). Use centralized log management (SIEM). "
            "Set alert thresholds for suspicious patterns (many failures, unusual hours, bulk exports). "
            "Sanitize log inputs to prevent log injection. Never log sensitive data (passwords, tokens). "
            "Define and rehearse an incident response plan."
        ),
    },
    {
        "id": "A10:2025",
        "title": "Mishandling of Exceptional Conditions",
        "cwe_ids": ["CWE-390", "CWE-391", "CWE-544", "CWE-755", "CWE-756"],
        "description": (
            "NEW in 2025. Replaces SSRF (moved out of the top 10). Covers situations where "
            "a program does not properly handle or recover from exceptional conditions such "
            "as errors, exceptions, or unexpected states. Issues include: swallowed exceptions "
            "that hide failures from operators; overly broad try/except/catch blocks that mask "
            "the root cause; returning partial/corrupt data on error without signaling failure; "
            "not releasing resources (file handles, DB connections, locks) when exceptions occur; "
            "and security checks that pass by default when an error occurs instead of failing safe."
        ),
        "examples": (
            "Example 1 -- Fail open: try: authorize(user) except: pass -- authorization exception "
            "is silently swallowed so the request proceeds as authorized. "
            "Example 2 -- Bare except: except Exception: continue in a loop hides repeated "
            "failures and continues processing corrupted data without alerting operators. "
            "Example 3 -- Resource leak: File opened in try block, exception thrown before "
            "close(); file handle leaked and file remains locked."
        ),
        "prevention": (
            "Use specific exception types -- never use bare except or catch-all handlers "
            "around security-critical code. Fail closed/safe: if an authorization check throws, "
            "deny access by default. Use try/finally or context managers (with statements) to "
            "guarantee resource cleanup. Log all unexpected exceptions with full context. "
            "Test error paths explicitly, not just happy paths. Use linters that flag "
            "broad exception handling (pylint broad-except, etc.)."
        ),
    },
]

# ---------------------------------------------------------------------------
# CWE entries -- common weaknesses with detection patterns
# ---------------------------------------------------------------------------

CWE_ENTRIES: list[dict[str, Any]] = [
    {
        "id": "CWE-89",
        "name": "SQL Injection",
        "description": (
            "The software constructs all or part of a SQL command using externally-influenced "
            "input from an upstream component but does not neutralize special elements that "
            "could modify the intended SQL command. Attackers can bypass authentication, "
            "extract data, modify records, or execute system commands."
        ),
        "detection_patterns": (
            "String concatenation in SQL: 'SELECT ... WHERE id=' + variable. "
            "Unparameterized execute() calls. Direct use of request parameters in SQL. "
            "Python: cursor.execute(f'...{var}') or cursor.execute('...%s' % var). "
            "Node.js: db.query(`SELECT * FROM users WHERE id=${req.params.id}`). "
            "PHP: $q = 'SELECT * FROM users WHERE id=' . $_GET['id']."
        ),
        "severity": "Critical",
        "languages": ["python", "javascript", "php", "java", "csharp"],
    },
    {
        "id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "description": (
            "The software does not neutralize user-controllable input before placing it in "
            "output served as a web page. Attackers inject client-side scripts to steal "
            "cookies, session tokens, or redirect users."
        ),
        "detection_patterns": (
            "innerHTML = userInput, document.write(userInput). "
            "Template engines: {{ userInput | safe }} or {!! userInput !!}. "
            "React: dangerouslySetInnerHTML={{ __html: userInput }}. "
            "Flask: return userInput without Markup.escape. "
            "Django: {{ userInput|safe }} or mark_safe(userInput)."
        ),
        "severity": "High",
        "languages": ["javascript", "python", "php", "java"],
    },
    {
        "id": "CWE-798",
        "name": "Hardcoded Credentials",
        "description": (
            "The software contains hardcoded credentials -- passwords, API keys, or "
            "cryptographic keys. These cannot be rotated without modifying source code "
            "and are typically leaked in version control history."
        ),
        "detection_patterns": (
            "password = 'hardcoded_string', api_key = 'sk-...'. "
            "AWS access keys: AKIA... pattern in source. "
            "Private keys inline: -----BEGIN RSA PRIVATE KEY-----. "
            "DB URLs with embedded passwords: postgresql://user:pass@host/db. "
            "SECRET_KEY = 'abc123' instead of os.environ.get('SECRET_KEY')."
        ),
        "severity": "Critical",
        "languages": ["python", "javascript", "java", "go", "ruby", "php"],
    },
    {
        "id": "CWE-78",
        "name": "OS Command Injection",
        "description": (
            "The software constructs an OS command using externally-influenced input but "
            "does not neutralize special elements. Attackers execute arbitrary commands "
            "on the host system."
        ),
        "detection_patterns": (
            "Python: os.system(user_input), subprocess.call(user_input, shell=True). "
            "Node.js: exec(userInput), execSync(`ls ${userInput}`). "
            "PHP: exec($_GET['cmd']), system($user_input), `$user_input`. "
            "Java: Runtime.exec(userInput). "
            "Any shell=True with string interpolation of user input."
        ),
        "severity": "Critical",
        "languages": ["python", "javascript", "php", "java", "ruby"],
    },
    {
        "id": "CWE-22",
        "name": "Path Traversal",
        "description": (
            "The software uses external input to construct a pathname but does not neutralize "
            "elements such as ../ that resolve to locations outside the restricted directory. "
            "Attackers can read or write arbitrary files."
        ),
        "detection_patterns": (
            "open(user_provided_path) without sanitization. "
            "os.path.join with user input not validated to stay within the base dir. "
            "send_file(filename) where filename is user-controlled. "
            "Missing os.path.realpath() validation after joining paths. "
            "'../' or '..\\\\' not stripped from user input."
        ),
        "severity": "High",
        "languages": ["python", "javascript", "php", "java"],
    },
    {
        "id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "description": (
            "The application deserializes untrusted data without sufficiently verifying "
            "validity. Can lead to remote code execution, replay attacks, or privilege escalation."
        ),
        "detection_patterns": (
            "Python: pickle.loads(user_data), yaml.load(data) without Loader=yaml.SafeLoader. "
            "Java: ObjectInputStream.readObject() with untrusted data. "
            "PHP: unserialize($_GET['data']). "
            "Node.js: eval(JSON.parse(untrusted)), node-serialize deserialize(). "
            "Any deserialization of HTTP body, cookie, or query parameter data."
        ),
        "severity": "Critical",
        "languages": ["python", "java", "php", "javascript"],
    },
    {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "description": (
            "The software does not restrict or incorrectly restricts access to a resource "
            "from unauthorized actors. Attackers can read or modify data, escalate privileges, "
            "or perform admin actions."
        ),
        "detection_patterns": (
            "Routes without auth decorators: @app.route('/admin') without @login_required. "
            "Object IDs fetched from request without owner verification. "
            "Role checks relying on client-supplied data. "
            "User.objects.get(id=request.GET['id']) without .filter(owner=request.user)."
        ),
        "severity": "High",
        "languages": ["python", "javascript", "java", "php"],
    },
    {
        "id": "CWE-311",
        "name": "Missing Encryption of Sensitive Data",
        "description": (
            "The software does not encrypt sensitive or critical information before storage "
            "or transmission. Exposed through breaches, log access, or traffic interception."
        ),
        "detection_patterns": (
            "Passwords stored with md5() or sha1() without salt. "
            "HTTP instead of HTTPS for sensitive endpoints. "
            "Sensitive data logged: logging.info(f'Password: {password}'). "
            "Credit card numbers or SSNs stored as plaintext. "
            "Missing bcrypt, argon2, or scrypt for password storage."
        ),
        "severity": "High",
        "languages": ["python", "javascript", "php", "java", "ruby"],
    },
    {
        "id": "CWE-755",
        "name": "Improper Handling of Exceptional Conditions",
        "description": (
            "The software does not handle or incorrectly handles an exceptional condition. "
            "Core weakness underlying OWASP A10:2025. Includes fail-open auth, swallowed "
            "exceptions, resource leaks on error paths, and security-relevant exceptions "
            "silently ignored."
        ),
        "detection_patterns": (
            "Bare except/catch-all: except Exception: pass or catch (Exception e) {}. "
            "Fail-open pattern: try: check_auth() except: pass -- auth failure silently allows access. "
            "Missing finally or context manager for resource cleanup. "
            "No logging in except blocks -- errors disappear silently. "
            "Boolean-returning auth functions that return True on exception."
        ),
        "severity": "High",
        "languages": ["python", "java", "javascript", "csharp", "go"],
    },
    {
        "id": "CWE-494",
        "name": "Download of Code Without Integrity Check",
        "description": (
            "The product downloads source code or an executable from a remote location and "
            "executes the code without sufficiently verifying the origin and integrity. "
            "Core weakness underlying OWASP A03:2025 Supply Chain Failures."
        ),
        "detection_patterns": (
            "pip install with no hash pinning: pip install requests (no --hash flag). "
            "requirements.txt without pinned exact versions and hashes. "
            "npm install with no lockfile or integrity field. "
            "curl | bash patterns in Dockerfiles or CI scripts. "
            "Unpinned base images: FROM python:latest instead of FROM python:3.12.3-slim."
        ),
        "severity": "High",
        "languages": ["python", "javascript", "go", "java"],
    },
]

# ---------------------------------------------------------------------------
# Language-specific exploit pattern reference docs
# ---------------------------------------------------------------------------

LANGUAGE_PATTERNS: list[dict[str, str]] = [
    {
        "language": "python",
        "title": "Python Security Anti-Patterns Reference",
        "content": (
            "DANGEROUS PYTHON PATTERNS:\n\n"
            "1. eval() and exec() with user input: eval(request.args.get('expr')) is RCE. "
            "Never pass user-controlled strings to eval/exec.\n\n"
            "2. pickle.loads(untrusted_bytes): executes arbitrary code on deserialization. "
            "Use JSON or msgpack for untrusted data.\n\n"
            "3. yaml.load(data) without SafeLoader: yaml.load allows arbitrary Python object "
            "construction. Always use yaml.safe_load().\n\n"
            "4. subprocess with shell=True and user input: subprocess.run(f'ls {user_path}', "
            "shell=True) is command injection. Use shell=False with a list of args.\n\n"
            "5. Hardcoded secrets: SECRET_KEY = 'abc123'. Use os.environ.get() or python-dotenv.\n\n"
            "6. Debug mode in production: app.run(debug=True) exposes Werkzeug debugger (RCE).\n\n"
            "7. SQL string formatting: cursor.execute(f'SELECT * FROM users WHERE id={id}'). "
            "Use parameterized: cursor.execute('SELECT * FROM users WHERE id=?', (id,)).\n\n"
            "8. Weak random for security: random.random() for tokens. Use secrets.token_hex().\n\n"
            "9. Bare except: except Exception: pass swallows failures silently (OWASP A10:2025).\n\n"
            "10. Fail-open auth: try: authorize(user) except: pass -- auth error grants access."
        ),
    },
    {
        "language": "javascript",
        "title": "JavaScript / Node.js Security Anti-Patterns Reference",
        "content": (
            "DANGEROUS JAVASCRIPT/NODE.JS PATTERNS:\n\n"
            "1. eval() with user input: eval(req.body.code) is direct RCE.\n\n"
            "2. SQL injection in Node: db.query(`SELECT * FROM users WHERE id=${req.params.id}`). "
            "Use parameterized queries.\n\n"
            "3. Command injection: child_process.exec(`ls ${userInput}`). "
            "Use execFile() with array args instead.\n\n"
            "4. Path traversal: fs.readFile(path.join('./files', req.query.filename)). "
            "Validate resolved path stays within base directory.\n\n"
            "5. XSS via innerHTML: element.innerHTML = userInput. Use textContent.\n\n"
            "6. Prototype pollution: lodash merge with user-controlled keys can pollute Object.prototype.\n\n"
            "7. Hardcoded secrets: const apiKey = 'sk-abc123'. Use process.env variables.\n\n"
            "8. SSRF: axios.get(req.body.url) without URL allowlist.\n\n"
            "9. JWT algorithm confusion: jwt.verify without explicit alg check allows 'none' attack.\n\n"
            "10. Swallowed promise rejections: .catch(() => {}) hides errors (OWASP A10:2025)."
        ),
    },
    {
        "language": "java",
        "title": "Java Security Anti-Patterns Reference",
        "content": (
            "DANGEROUS JAVA PATTERNS:\n\n"
            "1. SQL injection: Statement.execute('SELECT * FROM users WHERE id=' + userId). "
            "Use PreparedStatement.\n\n"
            "2. Insecure deserialization: ObjectInputStream.readObject() with untrusted data is RCE.\n\n"
            "3. XXE: DocumentBuilderFactory without FEATURE_SECURE_PROCESSING.\n\n"
            "4. Path traversal: new File(baseDir + userInput) without normalization.\n\n"
            "5. Hardcoded credentials: String password = 'admin123'.\n\n"
            "6. Weak crypto: MD5 or SHA-1 for password hashing. Use bcrypt or Argon2.\n\n"
            "7. Log4Shell: log4j < 2.17.1 with user input in log messages allows JNDI RCE.\n\n"
            "8. Spring mass assignment: @RequestBody binding to entity without DTO layer.\n\n"
            "9. Empty catch blocks: catch (Exception e) {} swallows failures silently.\n\n"
            "10. Missing @PreAuthorize: Spring endpoints without method-level security."
        ),
    },
    {
        "language": "go",
        "title": "Go Security Anti-Patterns Reference",
        "content": (
            "DANGEROUS GO PATTERNS:\n\n"
            "1. SQL injection: db.Query('SELECT * FROM users WHERE id=' + id).\n\n"
            "2. Command injection: exec.Command('sh', '-c', userInput).\n\n"
            "3. Path traversal: http.ServeFile without checking cleaned path stays under base.\n\n"
            "4. Hardcoded secrets: var apiKey = 'sk-abc'. Use os.Getenv().\n\n"
            "5. TLS InsecureSkipVerify: tls.Config{InsecureSkipVerify: true}.\n\n"
            "6. math/rand instead of crypto/rand for security-sensitive tokens.\n\n"
            "7. SSRF: http.Get(r.FormValue('url')) without URL validation.\n\n"
            "8. Race conditions: shared mutable state without sync.Mutex.\n\n"
            "9. Ignoring error returns: _, err := ...; if err is not checked, failures are silent.\n\n"
            "10. Goroutine leak: goroutines without context cancellation."
        ),
    },
]


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Split text into overlapping chunks.

    Uses LangChain's RecursiveCharacterTextSplitter when available so chunk
    boundaries fall on sentence/paragraph breaks rather than mid-word.
    Falls back to the simple character splitter if LangChain is not installed.

    Both paths produce chunks of at most `size` characters with `overlap`
    character overlap — the interface is identical for callers.
    """
    if len(text) <= size:
        return [text]

    try:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=size,
            chunk_overlap=overlap,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
        return [c for c in splitter.split_text(text) if c.strip()]
    except ImportError:
        # Fallback: simple character-level sliding window
        chunks = []
        start = 0
        while start < len(text):
            end = min(start + size, len(text))
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            start += size - overlap
        return chunks


# ---------------------------------------------------------------------------
# Ingest functions
# ---------------------------------------------------------------------------

def ingest_owasp(db: Chroma) -> int:
    """Embed and store OWASP Top 10 (2025) entries."""
    documents, ids = [], []
    for entry in OWASP_TOP_10:
        full_text = (
            f"OWASP {entry['id']} -- {entry['title']}\n\n"
            f"Description: {entry['description']}\n\n"
            f"Examples: {entry['examples']}\n\n"
            f"Prevention: {entry['prevention']}\n\n"
            f"Related CWEs: {', '.join(entry['cwe_ids'])}"
        )
        for idx, chunk in enumerate(chunk_text(full_text)):
            doc_id = f"owasp_{entry['id'].replace(':', '_')}_{idx}"
            documents.append(Document(
                page_content=chunk,
                metadata={
                    "source": "OWASP",
                    "owasp_id": entry["id"],
                    "title": entry["title"],
                    "cwe_ids": json.dumps(entry["cwe_ids"]),
                    "chunk_index": idx,
                },
            ))
            ids.append(doc_id)
    db.add_documents(documents=documents, ids=ids)
    log.info("OWASP: ingested %d entries -> %d chunks", len(OWASP_TOP_10), len(documents))
    return len(documents)


def ingest_cwe(db: Chroma) -> int:
    """Embed and store CWE reference entries."""
    documents, ids = [], []
    for entry in CWE_ENTRIES:
        full_text = (
            f"{entry['id']} -- {entry['name']}\n\n"
            f"Description: {entry['description']}\n\n"
            f"Detection Patterns: {entry['detection_patterns']}\n\n"
            f"Severity: {entry['severity']}\n"
            f"Affected Languages: {', '.join(entry['languages'])}"
        )
        for idx, chunk in enumerate(chunk_text(full_text)):
            doc_id = f"cwe_{entry['id'].replace('-', '_')}_{idx}"
            documents.append(Document(
                page_content=chunk,
                metadata={
                    "source": "CWE",
                    "cwe_id": entry["id"],
                    "name": entry["name"],
                    "severity": entry["severity"],
                    "languages": json.dumps(entry["languages"]),
                    "chunk_index": idx,
                },
            ))
            ids.append(doc_id)
    db.add_documents(documents=documents, ids=ids)
    log.info("CWE: ingested %d entries -> %d chunks", len(CWE_ENTRIES), len(documents))
    return len(documents)


def ingest_language_patterns(db: Chroma) -> int:
    """Embed and store language-specific exploit pattern docs."""
    documents, ids = [], []
    for entry in LANGUAGE_PATTERNS:
        for idx, chunk in enumerate(chunk_text(entry["content"])):
            doc_id = f"patterns_{entry['language']}_{idx}"
            documents.append(Document(
                page_content=chunk,
                metadata={
                    "source": "ExploitPatterns",
                    "language": entry["language"],
                    "title": entry["title"],
                    "chunk_index": idx,
                },
            ))
            ids.append(doc_id)
    db.add_documents(documents=documents, ids=ids)
    log.info("Language patterns: ingested %d entries -> %d chunks", len(LANGUAGE_PATTERNS), len(documents))
    return len(documents)


def ingest_nvd_batches(db: Chroma, raw_dir: str = RAW_DATA_DIR) -> int:
    """
    Ingest raw CVE JSON batches downloaded by 1_download_raw_cves.py.

    This is the bridge between the team's starter script and our RAG pipeline.
    The starter script saves batches as cve_batch_0.json, cve_batch_2000.json, etc.
    We read those and embed them into the same ChromaDB collection.
    """
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        log.warning("Raw data dir %s not found. Run 1_download_raw_cves.py first.", raw_dir)
        return 0

    batch_files = sorted(raw_path.glob("cve_batch_*.json"))
    if not batch_files:
        log.warning("No batch files found in %s", raw_dir)
        return 0

    total_chunks = 0
    for batch_file in batch_files:
        try:
            with batch_file.open(encoding="utf-8") as f:
                vulnerabilities = json.load(f)

            documents, ids = [], []
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                desc_text = next(
                    (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                    "No description.",
                )

                # Severity
                severity = "Unknown"
                metrics = cve_data.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        severity = metric_list[0].get("cvssData", {}).get("baseSeverity", severity)
                        break

                # CWEs
                cwe_ids = [
                    desc.get("value", "")
                    for w in cve_data.get("weaknesses", [])
                    for desc in w.get("description", [])
                    if desc.get("value", "").startswith("CWE-")
                ]

                full_text = (
                    f"{cve_id} - Severity: {severity}\n"
                    f"CWEs: {', '.join(cwe_ids) or 'None'}\n\n"
                    f"{desc_text}"
                )

                for chunk_idx, chunk in enumerate(chunk_text(full_text)):
                    doc_id = f"nvd_{cve_id.replace('-', '_')}_{chunk_idx}"
                    documents.append(Document(
                        page_content=chunk,
                        metadata={
                            "source": "NVD",
                            "cve_id": cve_id,
                            "severity": severity,
                            "chunk_index": chunk_idx,
                        },
                    ))
                    ids.append(doc_id)

            if documents:
                db.add_documents(documents=documents, ids=ids)
                total_chunks += len(documents)
                log.info("Ingested %s -> %d chunks", batch_file.name, len(documents))
        except Exception as exc:
            log.error("Failed to process %s: %s", batch_file.name, exc)

    log.info("NVD batches complete: %d total chunks", total_chunks)
    return total_chunks


def full_ingest() -> dict[str, int]:
    """Run the complete non-CVE ingest pipeline (OWASP + CWE + patterns)."""
    log.info("Starting full VulnScan KB ingest (OWASP 2025 + CWE + patterns)...")
    db = _get_db()
    results = {
        "owasp": ingest_owasp(db),
        "cwe": ingest_cwe(db),
        "patterns": ingest_language_patterns(db),
    }
    total = sum(results.values())
    log.info("Full ingest complete. Total chunks: %d. Breakdown: %s", total, results)
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan RAG Knowledge Base Ingest")
    parser.add_argument(
        "--source",
        choices=["owasp", "cwe", "patterns", "nvd_batches", "all"],
        default="all",
        help="Which data source to ingest (default: all)",
    )
    args = parser.parse_args()

    db = _get_db()
    if args.source == "all":
        full_ingest()
    elif args.source == "owasp":
        ingest_owasp(db)
    elif args.source == "cwe":
        ingest_cwe(db)
    elif args.source == "patterns":
        ingest_language_patterns(db)
    elif args.source == "nvd_batches":
        ingest_nvd_batches(db)
