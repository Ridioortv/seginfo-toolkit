resource "aws_security_group" "opensearch" {
  name        = "${var.project_name}-opensearch-sg"
  description = "Permite OpenSearch solo desde dentro de la VPC (nodos EKS)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "OpenSearch (HTTPS) desde la VPC"
    from_port   = 443
    to_port     = 443
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

resource "aws_opensearch_domain" "main" {
  domain_name    = "${var.project_name}-siem"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type  = var.opensearch_instance_type
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
    volume_type = "gp3"
  }

  vpc_options {
    subnet_ids         = [values(aws_subnet.private)[0].id]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https = true
  }
}
