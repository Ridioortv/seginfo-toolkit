resource "aws_db_subnet_group" "postgres" {
  name       = "${var.project_name}-postgres"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_security_group" "postgres" {
  name        = "${var.project_name}-postgres-sg"
  description = "Permite Postgres solo desde dentro de la VPC (nodos EKS)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Postgres desde la VPC"
    from_port   = 5432
    to_port     = 5432
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

resource "aws_db_instance" "postgres" {
  identifier             = "${var.project_name}-postgres"
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage_gb
  storage_encrypted      = true
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  vpc_security_group_ids = [aws_security_group.postgres.id]
  publicly_accessible    = false
  multi_az               = var.environment == "production"
  backup_retention_period = 7
  skip_final_snapshot    = var.environment != "production"
  deletion_protection    = var.environment == "production"
}
