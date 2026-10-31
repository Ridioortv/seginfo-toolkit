"""Procedencia: deteccion de IA en commits, lectura de git log y patrones inseguros en lineas agregadas."""
from app import provenance as p

# Los textos "parecidos a secretos" se arman por partes para que ningun escaner del repo los marque.
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
PRIVATE_KEY_LINE = "-----BEGIN " + "RSA PRIVATE KEY-----"


def test_commit_without_signals_is_human():
    prov = p.detect_provenance("fix: arregla el login", "Ana", "ana@acme.com")
    assert prov.origin == "human" and prov.detection == "default" and prov.ai_tool == ""


def test_coauthored_by_ai_is_mixed_with_tool_and_model():
    msg = "feat: nueva pantalla\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
    prov = p.detect_provenance(msg, "Ana", "ana@acme.com")
    assert prov.origin == "mixed" and prov.ai_tool == "Claude" and prov.ai_model == "Claude Sonnet 5.5"
    assert prov.detection == "trailer"


def test_copilot_and_cursor_are_recognised():
    assert p.detect_provenance("x\n\nCo-authored-by: Copilot <copilot@github.com>").ai_tool == "GitHub Copilot"
    assert p.detect_provenance("x\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>").ai_tool == "Cursor"


def test_author_that_is_a_bot_is_fully_ai():
    prov = p.detect_provenance("chore: deps", "copilot-swe-agent[bot]", "198982749+Copilot@users.noreply.github.com")
    assert prov.origin == "ai"


def test_explicit_trailers_win_over_inference():
    msg = "feat: x\n\nAI-Origin: ai\nAI-Tool: Aider\nAI-Model: gpt-5\nAI-Prompt: agrega paginacion al listado"
    prov = p.detect_provenance(msg, "Ana", "ana@acme.com")
    assert (prov.origin, prov.ai_tool, prov.ai_model, prov.prompt_ref) == ("ai", "Aider", "gpt-5", "agrega paginacion al listado")
    # una persona puede declarar que fue 100% humano aunque haya mencion de IA en el texto
    human = p.detect_provenance("docs: explica Claude\n\nAI-Origin: human")
    assert human.origin == "human"


def test_generated_with_and_assisted_by_are_mixed():
    assert p.detect_provenance("x\n\nGenerated with [Claude Code](https://claude.com/claude-code)").origin == "mixed"
    assert p.detect_provenance("x\n\nAssisted-by: Gemini 2.5").ai_tool == "Gemini"
    assert p.detect_provenance("x\n\nAI-Assisted: true").origin == "mixed"


def test_mentioning_ai_in_the_message_alone_does_not_count():
    assert p.detect_provenance("docs: agrega guia para usar Claude y Copilot").origin == "human"


LOG = (
    "\x1e" + "a" * 40 + "\x1fAna\x1fana@acme.com\x1f2026-10-01T10:00:00-03:00\x1ffeat: uno\n\ncuerpo\x1f\x1d\n"
    "3\t1\tsrc/a.py\n10\t0\tsrc/b.ts\n-\t-\timg/logo.png\n"
    "\x1e" + "b" * 40 + "\x1fLuis\x1fluis@acme.com\x1f2026-10-02T11:30:00+00:00\x1ffix: dos\x1f\x1d\n"
    "0\t4\tREADME.md\n"
)


def test_parse_git_log_numstat_and_dates():
    commits = p.parse_git_log(LOG)
    assert [c.sha[0] for c in commits] == ["a", "b"]
    first = commits[0]
    assert (first.lines_added, first.lines_removed) == (13, 1) and first.files == ["src/a.py", "src/b.ts", "img/logo.png"]
    assert first.committed_at.utcoffset() is not None and p.first_line(first.message) == "feat: uno"
    assert (commits[1].lines_added, commits[1].lines_removed) == (0, 4)


DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +2,4 @@
+import subprocess
+subprocess.run(cmd, shell=True)
+requests.get(url, verify=False)
+resultado = eval(entrada)
@@ -20,0 +25,2 @@
+query = f"SELECT * FROM users WHERE id = {user_id}"
+password = "SuperSecreta123"
diff --git a/docs.txt b/docs.txt
--- a/docs.txt
+++ b/docs.txt
@@ -0,0 +1 @@
+eval(esto es solo texto en un archivo que no es codigo)
"""


def test_scan_diff_finds_insecure_patterns_with_line_numbers():
    findings = p.scan_diff(DIFF)
    by_rule = {f["rule_id"]: f for f in findings}
    assert {"shell-true", "tls-verify-off", "eval-exec", "sql-concat", "hardcoded-secret"} <= set(by_rule)
    assert by_rule["shell-true"]["file"] == "app.py" and by_rule["shell-true"]["line"] == 3
    assert by_rule["sql-concat"]["line"] == 25
    assert by_rule["shell-true"]["severity"] == "high" and by_rule["hardcoded-secret"]["severity"] == "medium"
    assert all(f["file"] != "docs.txt" for f in findings)


def test_secret_like_findings_never_store_the_line_text():
    added = [("cfg.py", 1, f'key = "{AWS_KEY}"'), ("k.pem.py", 2, PRIVATE_KEY_LINE), ("c.py", 3, 'password = "SuperSecreta123"')]
    findings = p.scan_added_lines(added)
    assert {f["rule_id"] for f in findings} >= {"aws-access-key", "private-key", "hardcoded-secret"}
    assert all(f["snippet"] == "" for f in findings)
    assert {f["severity"] for f in findings if f["rule_id"] in ("aws-access-key", "private-key")} == {"critical"}


def test_clean_code_has_no_findings_and_placeholders_are_ignored():
    added = [("a.py", 1, "def suma(a, b):"), ("a.py", 2, "    return a + b"),
             ("a.py", 3, 'password = os.environ["DB_PASSWORD"]'), ("a.py", 4, 'api_key = "changeme-example-key"'),
             ("a.py", 5, "yaml.safe_load(texto)"), ("a.py", 6, "subprocess.run(['ls'], shell=False)")]
    assert p.scan_added_lines(added) == []


def test_findings_are_capped():
    added = [("a.py", i, "x = eval(y)") for i in range(500)]
    assert len(p.scan_added_lines(added)) == p.MAX_FINDINGS_PER_CHANGE
