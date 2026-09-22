output "vpc_id" {
  value = aws_vpc.main.id
}

output "eks_cluster_name" {
  value = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "postgres_endpoint" {
  description = "Host:puerto de RDS. Usar como POSTGRES_HOST en infra/k8s/base/configmap.yaml (sin el puerto) para produccion."
  value       = aws_db_instance.postgres.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  value     = aws_elasticache_cluster.redis.cache_nodes[0].address
  sensitive = true
}

output "opensearch_endpoint" {
  value     = aws_opensearch_domain.main.endpoint
  sensitive = true
}

output "ecr_repository_urls" {
  value = { for name, repo in aws_ecr_repository.service : name => repo.repository_url }
}
