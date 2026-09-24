"""Tests para el contrato de SLA por prioridad de case-service
(app/models.py::SLA_HOURS_BY_PRIORITY) y la formula que lo usa en
app/services.py::create_case (sla_due_at = ahora + timedelta(horas)).
Se prueba la formula directamente con timedelta, sin tocar la base --
create_case es async y depende de una sesion real, pero el calculo de la
fecha limite en si es puro."""
from datetime import timedelta

from app.models import CasePriority, SLA_HOURS_BY_PRIORITY


class TestSlaHoursByPriority:
    def test_all_priorities_have_an_sla(self):
        for priority in CasePriority:
            assert priority in SLA_HOURS_BY_PRIORITY

    def test_sla_gets_stricter_as_priority_increases(self):
        # critical debe vencer antes que high, high antes que medium, etc.
        assert SLA_HOURS_BY_PRIORITY[CasePriority.critical] < SLA_HOURS_BY_PRIORITY[CasePriority.high]
        assert SLA_HOURS_BY_PRIORITY[CasePriority.high] < SLA_HOURS_BY_PRIORITY[CasePriority.medium]
        assert SLA_HOURS_BY_PRIORITY[CasePriority.medium] < SLA_HOURS_BY_PRIORITY[CasePriority.low]

    def test_critical_sla_is_same_business_day(self):
        # contrato de producto: un caso critico vence en horas, no en dias.
        assert SLA_HOURS_BY_PRIORITY[CasePriority.critical] <= 8


class TestSlaDueAtFormula:
    def test_due_at_matches_priority_window(self):
        from datetime import datetime, timezone

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        due_at = now + timedelta(hours=SLA_HOURS_BY_PRIORITY[CasePriority.critical])
        assert due_at == datetime(2026, 1, 1, 4, tzinfo=timezone.utc)
