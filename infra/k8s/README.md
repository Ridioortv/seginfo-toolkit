# SentinelOps -- manifiestos de Kubernetes

Manifiestos base (Kustomize) que reproducen en un cluster de Kubernetes la
misma topologia que `docker-compose.yml` en desarrollo: los 11
microservicios backend, el frontend, y (solo para demo/desarrollo)
Postgres/Redis/OpenSearch corriendo dentro del cluster.

## Antes de aplicar

1. Construir y publicar las imagenes de cada servicio en un registry
   accesible por el cluster, con el tag que usan estos manifiestos
   (`sentinelops/<servicio>:latest`) o ajustar el tag en cada
   `*-service.yaml` / `frontend.yaml`. El workflow de CI
   (`.github/workflows/ci.yml`) hace el build de cada imagen; falta
   agregarle el paso de push a un registry real (GHCR, ECR, etc.) segun
   donde se despliegue.
2. Copiar `secret.yaml.example` a `secret.yaml` y completar
   `POSTGRES_PASSWORD` y `JWT_SECRET_KEY` con valores reales (nunca
   comitear `secret.yaml` -- ver `.gitignore` de esta carpeta). En
   produccion, reemplazar este Secret plano por un gestor externo
   (Sealed Secrets, External Secrets Operator + Vault/AWS Secrets
   Manager/GCP Secret Manager).
3. Para produccion, reemplazar `postgres.yaml` y `opensearch.yaml` por
   servicios administrados (ver `infra/terraform`) y apuntar
   `POSTGRES_HOST` / `OPENSEARCH_HOST` en `configmap.yaml` a esos
   endpoints en vez de a los Service internos del cluster.
4. Ajustar `ingress.yaml`: el `host` (`sentinelops.example.com`), el
   `ingressClassName` y el `cert-manager.io/cluster-issuer` al
   ingress-controller y proveedor de certificados reales del cluster.

## Aplicar

```
cd infra/k8s/base
kubectl apply -k .
```

## Notas de alcance

Todas las variables de doble dry-run (`SOAR_DRY_RUN`,
`INTEGRATION_DRY_RUN`, `NOTIFICATION_DRY_RUN`) quedan en `"true"` en
`configmap.yaml` -- igual que en `docker-compose.yml` -- porque desactivar
la simulacion es una decision explicita del operador, nunca el valor por
defecto de un manifiesto de despliegue. Ver `docs/architecture.md`,
seccion "Fuera de alcance", para el detalle completo de que NO hace esta
plataforma.

Estos manifiestos no fueron validados con `kubectl apply --dry-run` ni
`kustomize build` porque esas herramientas no estan disponibles en la
maquina de automatizacion que los genero -- si estan disponibles en tu
entorno, correlas antes de aplicar en un cluster real. El YAML de cada
archivo si fue validado como YAML sintacticamente valido.
