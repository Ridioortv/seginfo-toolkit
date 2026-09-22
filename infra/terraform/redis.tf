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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "${var.project_name}-redis"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.redis.name
  security_group_ids   = [aws_security_group.redis.id]
}
