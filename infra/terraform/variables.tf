variable "aws_region" {
  description = "Region de AWS donde se despliega la infraestructura."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Nombre del entorno (dev/staging/production)."
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Prefijo usado para nombrar los recursos."
  type        = string
  default     = "sentinelops"
}

variable "vpc_cidr" {
  description = "Bloque CIDR de la VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Zonas de disponibilidad a usar (al menos 2, para alta disponibilidad)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "microservices" {
  description = "Nombres de los microservicios backend, usados para crear un repositorio ECR por servicio."
  type        = list(string)
  default = [
    "auth-service", "asset-service", "scan-service", "vuln-service",
    "siem-service", "soar-service", "case-service", "purple-service",
    "report-service", "notification-service", "integration-service",
    "frontend",
  ]
}

variable "db_instance_class" {
  description = "Clase de instancia de RDS Postgres."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  description = "Almacenamiento asignado a RDS, en GB."
  type        = number
  default     = 20
}

variable "db_name" {
  type    = string
  default = "sentinelops"
}

variable "db_username" {
  type    = string
  default = "sentinelops"
}

variable "db_password" {
  description = "Password de la base de datos. Pasar via TF_VAR_db_password o un secret manager -- NUNCA hardcodear ni comitear en un .tfvars."
  type        = string
  sensitive   = true
}

variable "redis_auth_token" {
  description = "AUTH token de Redis (16-128 caracteres). Pasar via TF_VAR_redis_auth_token -- NUNCA hardcodear ni comitear."
  type        = string
  sensitive   = true
}

variable "opensearch_master_password" {
  description = "Contrasena del usuario maestro de OpenSearch (mayuscula, minuscula, numero y simbolo, 8+). Pasar via TF_VAR_opensearch_master_password."
  type        = string
  sensitive   = true
}

variable "eks_public_access_cidrs" {
  description = "CIDRs autorizados a llamar al API publico de EKS. Poner la IP de oficina/VPN (ej. [\"203.0.113.10/32\"]); no dejar 0.0.0.0/0 en produccion."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "opensearch_instance_type" {
  type    = string
  default = "t3.small.search"
}

variable "eks_node_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "eks_node_desired_size" {
  type    = number
  default = 3
}

variable "eks_node_min_size" {
  type    = number
  default = 2
}

variable "eks_node_max_size" {
  type    = number
  default = 6
}

variable "eks_kubernetes_version" {
  type    = string
  default = "1.30"
}
