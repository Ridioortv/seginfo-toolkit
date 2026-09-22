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
	waitForHealth(authHealth, 90*time.Second)

	fmt.Println()
	fmt.Println("Abriendo el dashboard en el navegador...")
	openBrowser(frontendURL)

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println(" SentinelOps esta corriendo.")
	fmt.Println(" Dashboard: " + frontendURL)
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

func waitForHealth(url string, timeout time.Duration) {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		fmt.Print(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Println()
	fmt.Println("El backend todavia no respondio -- puede que necesite un poco mas de")
	fmt.Println("tiempo (Postgres/OpenSearch tardan mas en el primer arranque). El")
	fmt.Println("dashboard se abre igual; si no carga, esperá un minuto y recargá la")
	fmt.Println("pagina.")
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
