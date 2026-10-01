# Imagen liviana solo para el agente de este bundle: no necesita
# nmap/trivy/nuclei (esos los cubren el Agente LAN/Agente Docker del
# stack principal) -- unicamente gvm-cli (paquete pip gvm-tools) para
# hablar GMP con el gvmd de este mismo bundle via el socket unix montado
# (ver docker-compose.yml, servicio openvas-agent).
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir gvm-tools

# Mismo remote-agent/agent.py que usan el Agente LAN/Agente Docker del
# stack principal -- un solo archivo fuente, sin forks: cualquier mejora
# futura (nuevos scanners, fixes) se escribe una vez y sirve para los 3.
COPY agent.py .

CMD ["python", "agent.py"]
