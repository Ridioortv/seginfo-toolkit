# Un repositorio ECR por microservicio (y el frontend). El workflow de CI
# (.github/workflows/ci.yml) hace el build de cada imagen; agregar ahi el
# paso de `docker push` a estos repositorios cuando se decida el registry
# final a usar.

resource "aws_ecr_repository" "service" {
  for_each             = toset(var.microservices)
  name                 = "${var.project_name}/${each.key}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "service" {
  for_each   = aws_ecr_repository.service
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Conservar solo las ultimas 20 imagenes"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}
