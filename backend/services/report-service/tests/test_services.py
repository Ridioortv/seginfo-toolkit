"""Tests de report-service/app/services.py: summarize_notify_result, la
funcion pura que determina el estado real de una corrida de reporte
programado a partir del body que devuelve POST /notify de
notification-service (NotifyResult.results). Sin ella, run_scheduled_report
marcaba `last_status = "ok"` con solo mirar el status HTTP (siempre 2xx),
aunque no se hubiera mandado ningun email real (canal deshabilitado/
borrado, o SMTP real fallido con `results` describiendo el fallo)."""
from app.services import summarize_notify_result


class TestSummarizeNotifyResult:
    def test_empty_results_is_failed(self):
        # Ningun canal matcheo el channel_id pedido (deshabilitado o
        # borrado despues de crear la regla) -- notify() igual responde
        # 200 con `results: []`, nadie recibe nada.
        assert summarize_notify_result([]) == "failed"

    def test_all_sent_is_ok(self):
        results = [
            {"channel_type": "email", "status": "sent", "error": ""},
            {"channel_type": "email", "status": "sent", "error": ""},
        ]
        assert summarize_notify_result(results) == "ok"

    def test_all_simulated_is_ok(self):
        # NOTIFICATION_DRY_RUN=true (default de la plataforma): "simulated"
        # es el comportamiento intencional, no un error de esta corrida.
        results = [{"channel_type": "email", "status": "simulated", "error": ""}]
        assert summarize_notify_result(results) == "ok"

    def test_single_failed_result_is_failed(self):
        results = [{"channel_type": "email", "status": "failed", "error": "SMTP_HOST no configurado en el entorno"}]
        assert summarize_notify_result(results) == "failed"

    def test_mixed_sent_and_failed_is_failed(self):
        # Con channel_ids=[channel_id] la regla programada solo le pide a
        # notify() un canal, asi que en la practica esta lista tiene un
        # solo elemento -- pero la funcion es generica (notify() acepta
        # varios channel_ids) y una corrida con al menos un canal fallido
        # nunca debe quedar registrada como "ok" silencioso.
        results = [
            {"channel_type": "email", "status": "sent", "error": ""},
            {"channel_type": "slack_webhook", "status": "failed", "error": "Connection refused"},
        ]
        assert summarize_notify_result(results) == "failed"

    def test_mixed_sent_and_simulated_is_ok(self):
        results = [
            {"channel_type": "email", "status": "sent", "error": ""},
            {"channel_type": "generic_webhook", "status": "simulated", "error": ""},
        ]
        assert summarize_notify_result(results) == "ok"
