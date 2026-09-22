"""Motor minimo de reglas estilo Sigma: evalua reglas de deteccion (bloques
`selection_*` + una `condition` booleana) contra eventos ya normalizados a
ECS. Es analisis sobre datos ya ingeridos -- nunca ejecuta ni dispara nada
por si mismo (ver services.py para que se hace con un match: crear un Alert).

Formato de `detection` (JSON, guardado en SigmaRule.detection):
{
  "selection_login_failure": {"event.action": "user_login", "event.outcome": "failure"},
  "selection_admin_targets": {"user.name": ["admin", "root"]},
  "condition": "selection_login_failure and selection_admin_targets"
}
Cada selection es un AND de sus campos; un campo con lista de valores es un
OR entre esos valores; se admite '*' como comodin simple (fnmatch)."""
import ast
import fnmatch
from app.ecs import get_by_path

_ALLOWED_CONDITION_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Name, ast.Load,
)


def _field_matches(event_value, expected) -> bool:
    candidates = expected if isinstance(expected, list) else [expected]
    event_str = "" if event_value is None else str(event_value)
    for candidate in candidates:
        candidate_str = str(candidate)
        if "*" in candidate_str:
            if fnmatch.fnmatch(event_str.lower(), candidate_str.lower()):
                return True
        elif event_str.lower() == candidate_str.lower():
            return True
    return False


def _selection_matches(event: dict, selection: dict) -> bool:
    return all(_field_matches(get_by_path(event, field), expected) for field, expected in selection.items())


def _safe_eval_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Evalua la condicion booleana de forma segura: se parsea a AST y se
    valida que solo contenga and/or/not/nombres de selection antes de
    evaluar (nunca se usa eval() sobre texto sin restricciones)."""
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id not in selection_results:
                return False
        elif not isinstance(node, _ALLOWED_CONDITION_NODES):
            return False

    code = compile(tree, "<sigma-condition>", "eval")
    return bool(eval(code, {"__builtins__": {}}, dict(selection_results)))


def evaluate_rule(event: dict, detection: dict) -> bool:
    """True si el evento cumple la `condition` de la regla."""
    condition = detection.get("condition", "")
    if not condition:
        return False
    selections = {name: block for name, block in detection.items() if name != "condition"}
    if not selections:
        return False
    results = {name: _selection_matches(event, block) for name, block in selections.items()}
    return _safe_eval_condition(condition, results)
