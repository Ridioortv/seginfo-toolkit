"""Tests de app/services.py: agent_can_claim_job -- la regla que decide,
para cada job candidato que trajo poll_agent_jobs, si el agente que esta
polleando se lo puede llevar. Sin esta regla, un agente bootstrap
("Agente Docker") tomaba CUALQUIER job 'pending' apenas se creaba, sin
importar a que agente lo habian mandado -- eso hacia que compitiera con
el otro bootstrap ("Agente LAN") por jobs pensados para el, y si Docker
ganaba la carrera contra un target de LAN lo rechazaba al toque (ver
AGENT_BEHIND_DOCKER_NAT en agent.py) antes de que Agente LAN -- online y
capaz -- tuviera la chance de correrlo el mismo.

Sin DB: la funcion es pura, recibe los atributos del job sueltos (no un
ORM object), asi que se testea pasandolos directo."""
from datetime import datetime, timedelta, timezone

from app.services import UNIVERSAL_WORKER_GRACE_SECONDS, agent_can_claim_job

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


class TestOwnPendingJob:
    def test_agent_can_always_claim_its_own_pending_job_immediately(self):
        # Sin importar si es bootstrap o no, ni cuando se creo: el job es
        # SUYO (agent_id coincide) y esta pending -> lo puede tomar ya.
        assert agent_can_claim_job(
            agent_id="agente-lan",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=NOW,
        ) is True

    def test_non_bootstrap_agent_can_claim_its_own_pending_job(self):
        assert agent_can_claim_job(
            agent_id="mi-pc-personal",
            is_bootstrap=False,
            job_agent_id="mi-pc-personal",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=NOW,
        ) is True


class TestOtherAgentsPendingJob:
    def test_bootstrap_agent_cannot_steal_a_fresh_job_sent_to_another_agent(self):
        # Este es el bug real que reporto Manu: un job recien creado para
        # "Agente LAN" no debe poder ser tomado por "Agente Docker" antes
        # de darle a Agente LAN la chance de pollear el suyo.
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=NOW,
        ) is False

    def test_bootstrap_agent_still_cannot_steal_it_just_before_the_grace_window(self):
        almost_there = NOW + timedelta(seconds=UNIVERSAL_WORKER_GRACE_SECONDS - 1)
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=almost_there,
        ) is False

    def test_bootstrap_agent_can_claim_it_as_fallback_once_grace_window_elapses(self):
        # Si Agente LAN nunca aparecio a pollear su job (ej. no corrio
        # agente-lan.ps1), Agente Docker lo toma igual como red de
        # contencion -- al menos reporta un error claro en vez de dejarlo
        # pending para siempre.
        after_grace = NOW + timedelta(seconds=UNIVERSAL_WORKER_GRACE_SECONDS)
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=after_grace,
        ) is True

    def test_non_bootstrap_agent_never_takes_another_agents_pending_job(self):
        after_grace = NOW + timedelta(seconds=UNIVERSAL_WORKER_GRACE_SECONDS * 10)
        assert agent_can_claim_job(
            agent_id="mi-pc-personal",
            is_bootstrap=False,
            job_agent_id="otro-agente",
            job_status="pending",
            job_created_at=NOW,
            job_assigned_at=None,
            now=after_grace,
        ) is False

    def test_pending_job_with_no_created_at_is_never_stolen(self):
        # No deberia pasar en la practica (created_at lo pone la DB al
        # crear la fila), pero si pasa, mejor no tomarlo que reventar con
        # un TypeError al restar None de una fecha.
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="pending",
            job_created_at=None,
            job_assigned_at=None,
            now=NOW,
        ) is False


class TestOrphanedAssignedJob:
    def test_bootstrap_agent_recovers_assigned_job_stale_for_over_10_minutes(self):
        assigned_at = NOW - timedelta(minutes=11)
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="assigned",
            job_created_at=NOW - timedelta(minutes=11),
            job_assigned_at=assigned_at,
            now=NOW,
        ) is True

    def test_bootstrap_agent_does_not_touch_a_recently_assigned_job(self):
        assigned_at = NOW - timedelta(minutes=2)
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="assigned",
            job_created_at=NOW - timedelta(minutes=2),
            job_assigned_at=assigned_at,
            now=NOW,
        ) is False

    def test_non_bootstrap_agent_never_recovers_assigned_jobs(self):
        assigned_at = NOW - timedelta(minutes=30)
        assert agent_can_claim_job(
            agent_id="mi-pc-personal",
            is_bootstrap=False,
            job_agent_id="otro-agente",
            job_status="assigned",
            job_created_at=NOW - timedelta(minutes=30),
            job_assigned_at=assigned_at,
            now=NOW,
        ) is False

    def test_assigned_job_with_no_assigned_at_is_never_recovered(self):
        assert agent_can_claim_job(
            agent_id="agente-docker",
            is_bootstrap=True,
            job_agent_id="agente-lan",
            job_status="assigned",
            job_created_at=NOW - timedelta(minutes=30),
            job_assigned_at=None,
            now=NOW,
        ) is False


class TestOtherStatuses:
    def test_completed_or_failed_jobs_are_never_claimable(self):
        for status in ("completed", "failed"):
            assert agent_can_claim_job(
                agent_id="agente-docker",
                is_bootstrap=True,
                job_agent_id="agente-docker",
                job_status=status,
                job_created_at=NOW - timedelta(hours=1),
                job_assigned_at=NOW - timedelta(hours=1),
                now=NOW,
            ) is False
