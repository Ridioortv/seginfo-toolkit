terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend remoto recomendado para cualquier uso mas alla de una prueba
  # local -- descomentar y ajustar antes de un `terraform init` real.
  # backend "s3" {
  #   bucket         = "CAMBIAR-nombre-bucket-tfstate"
  #   key            = "sentinelops/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "CAMBIAR-tabla-lock-terraform"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sentinelops"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
