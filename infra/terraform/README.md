# SentinelOps -- esqueleto de Terraform (AWS)

Infraestructura base de referencia para correr SentinelOps en AWS:
VPC (subredes publicas/privadas + NAT), un cluster EKS con un node
group administrado, RDS Postgres, ElastiCache Redis, un dominio
OpenSearch administrado, y un repositorio ECR por microservicio.

**Esto es un esqueleto de partida, no un modulo listo para produccion
tal cual.** Antes de aplicarlo contra una cuenta real hay que revisar
al menos:

- Costos: EKS + RDS + ElastiCache + OpenSearch + NAT gateway generan
  costo fijo mensual incluso sin trafico. Ajustar tamanios de instancia
  (`variables.tf`) al presupuesto real.
- Seguridad: los security groups aqui son deliberadamente simples
  (todo el trafico de la VPC puede llegar a Postgres/Redis/OpenSearch en
  su puerto). Para produccion, restringir a los security groups
  especificos de los nodos EKS en vez de todo el CIDR de la VPC.
- Estado remoto: el bloque `backend "s3"` en `versions.tf` esta
  comentado -- descomentar y configurar un bucket S3 + tabla DynamoDB de
  lock antes de usar Terraform en equipo (nunca versionar el
  `terraform.tfstate` local).
- `db_password` es una variable sensible sin default: pasarla por
  `TF_VAR_db_password` o un secret manager, nunca en un `.tfvars`
  comiteado.

## Uso

```
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # completar valores no sensibles
export TF_VAR_db_password="$(openssl rand -base64 24)"
terraform init
terraform plan
terraform apply
```

Despues de aplicar, `terraform output ecr_repository_urls` da las URLs
donde el CI debe publicar cada imagen, y `terraform output
eks_cluster_name` el nombre para configurar `kubectl`/`aws eks
update-kubeconfig` antes de aplicar los manifiestos de
`infra/k8s/base`.

## Validacion

Estos archivos fueron validados como HCL sintacticamente valido
(`python-hcl2`) en la maquina de automatizacion que los genero, porque
el binario de `terraform` no estaba disponible ahi. Correr `terraform
validate` y `terraform plan` en un entorno con AWS y Terraform
instalados antes de aplicar contra una cuenta real.
