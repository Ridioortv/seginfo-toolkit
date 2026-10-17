resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.project_name}-redis"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_security_group" "redis" {
  name        = "${var.project_name}-redis-sg"
  description = "Permite Redis solo desde dentro de la VPC (nodos EKS)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Redis desde la VPC"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Un data store no necesita salir a internet: egress solo hacia la VPC.
  egress {
    description = "Trafico de respuesta dentro de la VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
}

# Replication group (en vez de aws_elasticache_cluster) porque es lo que permite
# cifrado en transito + AUTH token. Los servicios deben conectarse con
# REDIS_SSL=true y REDIS_PASSWORD=<redis_auth_token>.
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.project_name}-redis"
  description                = "Rate limiting / cache de SentinelOps"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_auth_token
  automatic_failover_enabled = false
}
