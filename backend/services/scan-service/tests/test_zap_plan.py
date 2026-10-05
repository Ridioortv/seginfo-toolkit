import json

from app.scanners.zap import build_zap_plan


def test_plan_is_passive_only_and_bounded():
    plan = json.loads(build_zap_plan("http://x.test/a?b=1&c=\"2\"", "/tmp/r", "out.json"))
    types = [j["type"] for j in plan["jobs"]]
    assert types == ["spider", "passiveScan-wait", "report"]
    assert "activeScan" not in types
    assert plan["env"]["contexts"][0]["urls"] == ["http://x.test/a?b=1&c=\"2\""]
    assert plan["jobs"][0]["parameters"]["maxDuration"] > 0
    assert plan["jobs"][1]["parameters"]["maxDuration"] > 0
    assert plan["jobs"][2]["parameters"]["template"] == "traditional-json"
