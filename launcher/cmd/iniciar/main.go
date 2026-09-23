// SentinelOps - Iniciar.exe
//
// Launcher para Windows que levanta toda la plataforma SentinelOps
// (12 microservicios + Postgres/Redis/OpenSearch) con Docker Compose y
// abre el dashboard en el navegador. No reemplaza a Docker: sigue
// haciendo falta tener Docker Desktop instalado en la PC.
//
// Pensado para vivir en la raiz del repo (junto a docker-compose.yml) y
// ejecutarse con doble click. Ver launcher/README.md para como
// recompilarlo.
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const frontendURL = "http://localhost:5173"

// service representa un microservicio backend que el launcher tiene que
// confirmar que arranco de verdad (no alcanza con que "docker compose
// up" diga que el contenedor arranco: un contenedor puede arrancar y
// morirse un segundo despues, y sin este chequeo el usuario terminaba
// viendo el dashboard "listo" con la mitad de las paginas rotas).
type service struct {
	name      string // nombre del servicio en docker-compose.yml (para logs/ps)
	healthURL string
}

var services = []service{
	{"auth-service", "http://localhost:8001/health"},
	{"asset-service", "http://localhost:8002/health"},
	{"scan-service", "http://localhost:8003/health"},
	{"vuln-service", "http://localhost:8004/health"},
	{"siem-service", "http://localhost:8005/health"},
	{"soar-service", "http://localhost:8006/health"},
	{"case-service", "http://localhost:8007/health"},
	{"purple-service", "http://localhost:8008/health"},
	{"report-service", "http://localhost:8009/health"},
	{"notification-service", "http://localhost:8010/health"},
	{"integration-service", "http://localhost:8011/health"},
}

func main() {
	fmt.Println("========================================")
	fmt.Println(" SentinelOps - iniciando la plataforma")
	fmt.Println("========================================")
	fmt.Println()

	projectDir := projectRoot()
	fmt.Printf("Carpeta del proyecto: %s\n\n", projectDir)

	if err := os.Chdir(projectDir); err != nil {
		fatal("No se pudo entrar a la carpeta del proyecto: %v", err)
	}

	ensureDockerInstalled()
	ensureDockerRunning()
	ensureEnvFile(projectDir)

	fmt.Println()
	fmt.Println("Levantando los servicios con Docker Compose (puede tardar varios")
	fmt.Println("minutos la primera vez, porque construye cada imagen)...")
	fmt.Println()

	if err := runStreaming("docker", "compose", "up", "-d", "--build"); err != nil {
		fatal("\n'docker compose up' fallo: %v\n\nRevisa el detalle de arriba para ver que servicio dio error.", err)
	}

	// Los contenedores tienen restart:unless-stopped, asi que si alguno
	// se cae al arrancar (por ejemplo por una condicion de carrera al
	// crear tablas mientras arrancan 15 contenedores a la vez), Docker
	// lo reinicia solo -- pero eso tarda unos segundos por intento, asi
	// que damos varios minutos de margen antes de declarar que algo
	// esta realmente roto.
	fmt.Println()
	fmt.Println("Esperando a que los 11 microservicios respondan (puede tardar un par")
	fmt.Println("de minutos mientras Postgres/Redis/OpenSearch terminan de arrancar y")
	fmt.Println("los contenedores que se reinicien solos vuelven a levantar)...")
	fmt.Println()

	failed := waitForAllServices(services, 180*time.Second)

	fmt.Println()
	fmt.Println("Esperando a que el frontend responda...")
	frontendOK := waitForURL(frontendURL, 60*time.Second)
	if !frontendOK {
		fmt.Println()
		fmt.Println("El frontend todavia no respondio. Esto es lo que dice su log:")
		printLogs("frontend", 40)
	}

	if len(failed) > 0 || !frontendOK {
		fmt.Println()
		fmt.Println("========================================")
		fmt.Println(" Estos servicios NO respondieron a tiempo:")
		for _, s := range failed {
			fmt.Printf("  - %s\n", s.name)
		}
		if !frontendOK {
			fmt.Println("  - frontend")
		}
		fmt.Println("========================================")
		fmt.Println()
		fmt.Println("El log real de cada uno (la causa del error esta generalmente en las")
		fmt.Println("ultimas lineas de cada bloque):")
		for _, s := range failed {
			fmt.Println()
			fmt.Printf("---- %s ----\n", s.name)
			printLogs(s.name, 50)
		}

		fmt.Println()
		fmt.Println("Estado de todos los contenedores (docker compose ps):")
		runStreaming("docker", "compose", "ps", "-a")
	}

	fmt.Println()
	fmt.Println("========================================")
	if len(failed) == 0 && frontendOK {
		fmt.Println(" SentinelOps esta corriendo. Los 11 microservicios y el frontend")
		fmt.Println(" respondieron correctamente.")
		fmt.Println(" Dashboard: " + frontendURL)
		fmt.Println()
		fmt.Println(" Abriendo el dashboard en el navegador...")
		openBrowser(frontendURL)
	} else {
		fmt.Println(" SentinelOps arranco los contenedores, pero al menos uno todavia")
		fmt.Println(" no responde (ver el detalle y los logs de arriba). No se abre el")
		fmt.Println(" navegador solo para no confundir -- si necesitas ayuda, copia todo")
		fmt.Println(" el texto de esta ventana (desde 'NO respondieron a tiempo' hacia")
		fmt.Println(" abajo) y compartelo. Despues de revisar el error, es seguro volver")
		fmt.Println(" a correr este programa (docker compose up es idempotente).")
	}
	fmt.Println()
	fmt.Println(" Los servicios siguen funcionando en segundo plano aunque")
	fmt.Println(" cierres esta ventana. Para pararlos, usa")
	fmt.Println(" 'SentinelOps - Detener.exe'.")
	fmt.Println("========================================")
	pause()
}

// waitForAllServices sondea el /health de cada servicio en paralelo
// hasta que todos respondan (o se agote el tiempo), mostrando progreso
// en pantalla. Devuelve la lista de los que NO llegaron a responder.
func waitForAllServices(svcs []service, timeout time.Duration) []service {
	type result struct {
		svc service
		ok  bool
	}

	resultsCh := make(chan result, len(svcs))
	for _, s := range svcs {
		s := s
		go func() {
			resultsCh <- result{s, waitForURL(s.healthURL, timeout)}
		}()
	}

	var failed []service
	for i := 0; i < len(svcs); i++ {
		r := <-resultsCh
		status := "OK"
		if !r.ok {
			status = "NO RESPONDIO"
			failed = append(failed, r.svc)
		}
		fmt.Printf("  %-24s %s\n", r.svc.name, status)
	}
	return failed
}

// projectRoot devuelve la carpeta donde vive este .exe -- se asume que
// esta en la raiz del repo, junto a docker-compose.yml.
func projectRoot() string {
	exePath, err := os.Executable()
	if err != nil {
		fatal("No se pudo determinar la ubicacion del programa: %v", err)
	}
	return filepath.Dir(exePath)
}

func ensureDockerInstalled() {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("No se encontro Docker instalado en esta PC.")
		fmt.Println()
		fmt.Println("SentinelOps necesita Docker Desktop para funcionar. Instalalo desde:")
		fmt.Println("  https://www.docker.com/products/docker-desktop/")
		fmt.Println()
		fmt.Println("Despues de instalarlo (y abrirlo al menos una vez), volve a ejecutar")
		fmt.Println("este programa.")
		openBrowser("https://www.docker.com/products/docker-desktop/")
		pause()
		os.Exit(1)
	}
}

func ensureDockerRunning() {
	if dockerReady() {
		return
	}

	fmt.Println("Docker Desktop no esta corriendo. Intentando iniciarlo...")
	tryStartDockerDesktop()

	fmt.Print("Esperando a que Docker Desktop termine de arrancar")
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if dockerReady() {
			fmt.Println(" listo.")
			return
		}
		fmt.Print(".")
		time.Sleep(3 * time.Second)
	}

	fmt.Println()
	fatal("Docker Desktop no arranco a tiempo. Abrilo manualmente desde el menu\nInicio, espera a que el icono de la ballena este quieto (no animado),\ny volve a correr este programa.")
}

func dockerReady() bool {
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func tryStartDockerDesktop() {
	candidates := []string{
		`C:\Program Files\Docker\Docker\Docker Desktop.exe`,
		os.ExpandEnv(`${ProgramFiles}\Docker\Docker\Docker Desktop.exe`),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			_ = exec.Command(path).Start()
			return
		}
	}
	// Como ultimo recurso, dejar que Windows lo busque por nombre.
	_ = exec.Command("cmd", "/c", "start", "", "Docker Desktop").Start()
}

// ensureEnvFile copia .env.example a .env en el primer uso, para que la
// plataforma tenga algo con que arrancar sin pasos manuales.
func ensureEnvFile(projectDir string) {
	envPath := filepath.Join(projectDir, ".env")
	if _, err := os.Stat(envPath); err == nil {
		return
	}
	examplePath := filepath.Join(projectDir, ".env.example")
	data, err := os.ReadFile(examplePath)
	if err != nil {
		fatal("No se encontro .env ni .env.example en %s -- ¿esta este programa\nen la raiz del repo, junto a docker-compose.yml?", projectDir)
	}
	if err := os.WriteFile(envPath, data, 0o644); err != nil {
		fatal("No se pudo crear .env: %v", err)
	}
	fmt.Println("Primera vez: se creo .env a partir de .env.example (valores de demo,")
	fmt.Println("no para produccion -- ver docs/runbook.md).")
}

func runStreaming(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// waitForURL sondea una URL hasta que responda con HTTP 200 o se agote
// el tiempo. Antes se aceptaba cualquier respuesta (incluso 4xx/5xx),
// pero eso hacia que un servicio roto que devuelve 500 en /health se
// contara como "arriba" -- ahora se exige 200 puntual, que es lo que
// devuelve el endpoint /health de cada microservicio cuando esta bien.
func waitForURL(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			ok := resp.StatusCode == http.StatusOK
			resp.Body.Close()
			if ok {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// printLogs corre 'docker compose logs' para un servicio puntual, para
// que el usuario (o quien lo ayude) vea la causa real sin tener que
// abrir una terminal aparte.
func printLogs(service string, tailLines int) {
	cmd := exec.Command("docker", "compose", "logs", "--tail", fmt.Sprintf("%d", tailLines), service)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	_ = cmd.Run()
}

func openBrowser(url string) {
	_ = exec.Command("cmd", "/c", "start", "", url).Start()
}

func pause() {
	fmt.Println()
	fmt.Println("Presiona ENTER para cerrar esta ventana...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func fatal(format string, args ...interface{}) {
	fmt.Println()
	fmt.Printf(format+"\n", args...)
	pause()
	os.Exit(1)
}
