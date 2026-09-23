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

const (
	frontendURL = "http://localhost:5173"
	authHealth  = "http://localhost:8001/health"
)

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

	fmt.Println()
	fmt.Println("Esperando a que el backend responda...")
	authOK := waitForURL(authHealth, 90*time.Second)
	if !authOK {
		fmt.Println()
		fmt.Println("auth-service todavia no respondio. Esto es lo que dice su log:")
		printLogs("auth-service", 40)
	}

	fmt.Println()
	fmt.Println("Esperando a que el frontend responda...")
	frontendOK := waitForURL(frontendURL, 60*time.Second)
	if !frontendOK {
		fmt.Println()
		fmt.Println("El frontend todavia no respondio. Esto es lo que dice su log:")
		printLogs("frontend", 40)
	}

	if !authOK || !frontendOK {
		fmt.Println()
		fmt.Println("Estado de todos los contenedores (docker compose ps):")
		runStreaming("docker", "compose", "ps")
	}

	fmt.Println()
	fmt.Println("========================================")
	if authOK && frontendOK {
		fmt.Println(" SentinelOps esta corriendo.")
		fmt.Println(" Dashboard: " + frontendURL)
		fmt.Println()
		fmt.Println(" Abriendo el dashboard en el navegador...")
		openBrowser(frontendURL)
	} else {
		fmt.Println(" SentinelOps arranco los contenedores, pero al menos uno todavia")
		fmt.Println(" no responde (ver el log de arriba). No se abre el navegador solo")
		fmt.Println(" para no confundir -- revisa el error, arreglalo si hace falta, y")
		fmt.Println(" volve a correr este programa (es seguro repetirlo).")
	}
	fmt.Println()
	fmt.Println(" Los servicios siguen funcionando en segundo plano aunque")
	fmt.Println(" cierres esta ventana. Para pararlos, usa")
	fmt.Println(" 'SentinelOps - Detener.exe'.")
	fmt.Println("========================================")
	pause()
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

// waitForURL sondea una URL hasta que responda (cualquier respuesta HTTP
// cuenta, incluso un error 4xx/5xx -- lo que importa es que algo este
// escuchando en ese puerto) o se agote el tiempo. Devuelve true si
// respondio a tiempo.
func waitForURL(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
		fmt.Print(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Println()
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
