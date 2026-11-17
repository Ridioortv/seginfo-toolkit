"""Procedencia del codigo: de un `git log` saca quien escribio cada cambio (persona, IA o ambos) y
revisa las lineas AGREGADAS buscando patrones inseguros. Todo son funciones puras (sin DB ni red):
solo se LEE texto del repositorio clonado, nunca se ejecuta nada de su contenido."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- Deteccion de IA en el commit -------------------------------------------------------------

# (regex sobre el texto de co-autoria / mensaje / autor, nombre de la herramienta)
_AI_TOOLS: list[tuple[re.Pattern, str]] = [(re.compile(p, re.I), name) for p, name in [
    (r"claude|anthropic", "Claude"),
    (r"copilot", "GitHub Copilot"),
    (r"cursor(?:\.sh|\s*agent|\b)", "Cursor"),
    (r"codex|chatgpt|openai|gpt-\d", "OpenAI"),
    (r"gemini|jules", "Gemini"),
    (r"devin", "Devin"),
    (r"aider", "Aider"),
    (r"windsurf|codeium", "Windsurf"),
    (r"tabnine", "Tabnine"),
    (r"amazon\s*q|codewhisperer", "Amazon Q"),
    (r"cody\b|sourcegraph", "Cody"),
]]

_TRAILER_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+?)\s*$")
_COAUTHOR_RE = re.compile(r"^\s*co-authored-by\s*:\s*(.+?)\s*$", re.I | re.M)
_GENERATED_RE = re.compile(r"generated (?:with|by)\s*(?:\[)?([^\]\n(]+)", re.I)
_BOT_AUTHOR_RE = re.compile(
    r"(copilot-swe-agent|github-copilot|devin-ai|noreply@anthropic\.com|claude\[bot\]|aider|cursoragent|\[bot\])", re.I
)
VALID_ORIGINS = ("human", "ai", "mixed")


@dataclass
class Provenance:
    origin: str = "human"
    ai_tool: str = ""
    ai_model: str = ""
    prompt_ref: str = ""
    detection: str = "default"


def _tool_from(text: str) -> str:
    for pattern, name in _AI_TOOLS:
        if pattern.search(text):
            return name
    return ""


def trailers(message: str) -> dict[str, str]:
    """Trailers tipo `Clave: valor` (ultimo bloque del mensaje o cualquier linea `AI-*`)."""
    found: dict[str, str] = {}
    for line in message.splitlines():
        m = _TRAILER_RE.match(line)
        if m and (m.group(1).lower().startswith(("ai-", "assisted-by", "generated-by", "prompt"))):
            found[m.group(1).lower()] = m.group(2)[:500]
    return found


def detect_provenance(message: str, author_name: str = "", author_email: str = "") -> Provenance:
    """Origen de un commit a partir de sus senales explicitas:
      1. Trailers propios: `AI-Origin: ai|human|mixed`, `AI-Tool`, `AI-Model`, `AI-Prompt`.
      2. `Co-Authored-By: <IA>` -> mixto (persona + IA); autor que es un bot/IA -> ia.
      3. `Assisted-by:` / `AI-Assisted: true` / "Generated with <IA>" -> mixto.
    Sin senales -> humano. Es una DETECCION: una persona puede declarar o corregir el origen
    (queda en el registro auditable) porque nada garantiza que un commit lleve la marca."""
    t = trailers(message)
    prov = Provenance()
    prov.ai_tool = t.get("ai-tool", "")[:100]
    prov.ai_model = t.get("ai-model", "")[:150]
    prov.prompt_ref = (t.get("ai-prompt") or t.get("prompt") or "")[:500]

    explicit = t.get("ai-origin", "").lower()
    if explicit in VALID_ORIGINS:
        prov.origin, prov.detection = explicit, "trailer"
        return prov

    ai_signal = False
    coauthors = _COAUTHOR_RE.findall(message)
    for co in coauthors:
        tool = _tool_from(co)
        if tool:
            ai_signal = True
            prov.ai_tool = prov.ai_tool or tool
            name = re.sub(r"<[^>]*>", "", co).strip()
            prov.ai_model = prov.ai_model or name[:150]
    gen = _GENERATED_RE.search(message)
    if gen and _tool_from(gen.group(1)):
        ai_signal = True
        prov.ai_tool = prov.ai_tool or _tool_from(gen.group(1))
    assisted = t.get("assisted-by") or t.get("generated-by")
    if assisted and _tool_from(assisted):
        ai_signal = True
        prov.ai_tool = prov.ai_tool or _tool_from(assisted)
        prov.ai_model = prov.ai_model or assisted[:150]
    if t.get("ai-assisted", "").lower() in ("true", "yes", "si", "1"):
        ai_signal = True

    author_is_bot = bool(_BOT_AUTHOR_RE.search(f"{author_name} {author_email}"))
    if author_is_bot:
        prov.origin, prov.detection = "ai", "trailer"
        prov.ai_tool = prov.ai_tool or _tool_from(f"{author_name} {author_email}") or "Bot"
    elif ai_signal:
        prov.origin, prov.detection = "mixed", "trailer"
    return prov


# --- Lectura de `git log` ---------------------------------------------------------------------

GIT_LOG_ARGS = ["log", "--no-merges", "--numstat", "--date=iso-strict",
                "--pretty=format:%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f%B%x1f%x1d"]


@dataclass
class ParsedCommit:
    sha: str
    author_name: str
    author_email: str
    committed_at: datetime
    message: str
    lines_added: int = 0
    lines_removed: int = 0
    files: list[str] = field(default_factory=list)


def _parse_iso(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return datetime.now(timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_git_log(raw: str) -> list[ParsedCommit]:
    commits: list[ParsedCommit] = []
    for chunk in raw.split("\x1e"):
        if "\x1d" not in chunk:
            continue
        head, _, numstat = chunk.partition("\x1d")
        parts = head.split("\x1f")
        if len(parts) < 5 or not parts[0].strip():
            continue
        c = ParsedCommit(
            sha=parts[0].strip(), author_name=parts[1].strip(), author_email=parts[2].strip(),
            committed_at=_parse_iso(parts[3]), message=parts[4].strip(),
        )
        for line in numstat.splitlines():
            cols = line.split("\t")
            if len(cols) != 3:
                continue
            add, rem, path = cols
            c.files.append(path)
            if add.isdigit():
                c.lines_added += int(add)
            if rem.isdigit():
                c.lines_removed += int(rem)
        commits.append(c)
    return commits


def first_line(message: str, limit: int = 300) -> str:
    return (message.strip().splitlines() or [""])[0][:limit]


# --- Patrones inseguros en las lineas agregadas -----------------------------------------------

@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str  # critical | high | medium | low
    description: str
    pattern: re.Pattern
    hide_match: bool = False  # True: no se guarda ni se muestra el texto de la linea


def _r(rule_id, severity, description, pattern, hide=False, flags=re.I):
    return Rule(rule_id, severity, description, re.compile(pattern, flags), hide)


RULES: list[Rule] = [
    _r("private-key", "critical", "Clave privada en el codigo", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", True, 0),
    _r("aws-access-key", "critical", "Clave de acceso de AWS en el codigo", r"\bAKIA[0-9A-Z]{16}\b", True, 0),
    _r("eval-exec", "high", "eval()/exec() sobre datos dinamicos", r"(?<![\w.])(?:eval|exec)\s*\((?!\s*[\"']\s*[\"']\s*\))", flags=0),
    _r("shell-true", "high", "subprocess con shell=True (inyeccion de comandos)", r"shell\s*=\s*True"),
    _r("os-system", "medium", "os.system(): ejecuta comandos del sistema", r"\bos\.system\s*\("),
    _r("tls-verify-off", "high", "Verificacion TLS desactivada",
       r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
    _r("sql-concat", "high", "Consulta SQL armada con texto (posible inyeccion SQL)",
       r"f[\"'][^\"']*\b(?:select|insert|update|delete)\b[^\"']*\{[^}]+\}|[\"'][^\"']*\b(?:select|insert|update|delete)\b[^\"']*[\"']\s*(?:\+|%)\s*\w"),
    _r("unsafe-deserialize", "high", "Deserializacion insegura (pickle / yaml.load sin SafeLoader)",
       r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*(?:SafeLoader|safe_load))"),
    _r("hardcoded-secret", "medium", "Credencial escrita en el codigo",
       r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"'](?!\s*[\"'])(?![^\"']*(?:changeme|example|your[_-]|xxx|<|\$\{|process\.env|os\.environ))[^\"'\s]{8,}[\"']",
       True),
    _r("weak-hash", "medium", "Hash debil (MD5/SHA-1)", r"\bhashlib\.(?:md5|sha1)\s*\(|createHash\(\s*[\"'](?:md5|sha1)[\"']"),
    _r("weak-random", "medium", "Aleatoriedad no segura para tokens o claves",
       r"(?:token|password|secret|session|key|nonce).{0,40}(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice)\s*\()"
       r"|(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice)\s*\().{0,40}(?:token|password|secret|session|nonce)"),
    _r("xss-sink", "medium", "Inserta HTML sin sanear (XSS)", r"dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\("),
    _r("cors-wildcard", "medium", "CORS abierto a cualquier origen",
       r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']?\*"),
    _r("chmod-777", "medium", "Permisos 777 (cualquiera escribe)", r"\bchmod\s+(?:-R\s+)?0?777\b"),
    _r("pipe-to-shell", "medium", "Descarga y ejecuta un script remoto (curl | sh)", r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
    _r("debug-on", "low", "Modo debug activado", r"\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True"),
]

_CODE_EXT = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs", ".kt",
    ".sh", ".bash", ".ps1", ".yml", ".yaml", ".tf", ".json", ".env", ".sql", ".html", ".vue", ".swift",
)
MAX_FINDINGS_PER_CHANGE = 50
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_diff_added_lines(diff_text: str) -> list[tuple[str, int, str]]:
    """(archivo, nro de linea, texto) de cada linea AGREGADA de un diff unificado (`git show -U0`)."""
    out: list[tuple[str, int, str]] = []
    path = ""
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = target[2:] if target.startswith("b/") else ("" if target == "/dev/null" else target)
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            new_line = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if path:
                out.append((path, new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            continue
        else:
            new_line += 1 if raw.startswith(" ") else 0
    return out


def scan_added_lines(added: list[tuple[str, int, str]]) -> list[dict]:
    findings: list[dict] = []
    for path, line_no, text in added:
        if not path.lower().endswith(_CODE_EXT) and "Dockerfile" not in path:
            continue
        if len(text) > 2000:
            text = text[:2000]
        for rule in RULES:
            if rule.pattern.search(text):
                findings.append({
                    "source": "pattern", "rule_id": rule.rule_id, "severity": rule.severity,
                    "description": rule.description, "file": path[:300], "line": line_no,
                    "snippet": "" if rule.hide_match else text.strip()[:140],
                })
                if len(findings) >= MAX_FINDINGS_PER_CHANGE:
                    return findings
    return findings


def scan_diff(diff_text: str) -> list[dict]:
    return scan_added_lines(parse_diff_added_lines(diff_text))


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), default=str)


def loads_list(text: str | None) -> list:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []
