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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// randomHexSecret genera un secreto hexadecimal criptograficamente
// aleatorio de numBytes bytes (numBytes*2 caracteres hex) usando
// crypto/rand (nunca math/rand, que es predecible y NO apto para
// secretos).
func randomHexSecret(numBytes int) string {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		fatal("No se pudo generar un secreto aleatorio (crypto/rand): %v", err)
	}
	return hex.EncodeToString(b)
}

// generatedSecretKeys son las variables de .env.example cuyo valor de
// ejemplo ("changeme...") NUNCA debe llegar a usarse en una instalacion
// real -- cada una se reemplaza por un secreto random propio de ESTA
// instalacion, generado una sola vez (la primera vez que se crea .env;
// una vez que el archivo existe, ensureEnvFile no lo vuelve a tocar).
//
// Por que esto importa: antes, ensureEnvFile copiaba .env.example BYTE
// POR BYTE. Como este programa se distribuye empaquetado (un .rar) a
// todos los clientes, TODOS terminaban con el MISMO JWT_SECRET_KEY, la
// MISMA POSTGRES_PASSWORD y la MISMA ENCRYPTION_KEY -- cualquiera con
// una copia del instalador (todo cliente que pago, y quien sea que la
// filtre) podia firmar un JWT valido para la instalacion de OTRO
// cliente (incluyendo uno con platform_admin=true, ver
// backend/shared/security.py), conectarse directo a su Postgres
// expuesto en el puerto 5432, o descifrar el client_secret de SSO y las
// credenciales de sus conectores de contencion/ticketing (ver
// backend/shared/crypto.py).
var generatedSecretKeys = map[string]func() string{
	"JWT_SECRET_KEY":    func() string { return randomHexSecret(32) }, // 256 bits
	"POSTGRES_PASSWORD": func() string { return randomHexSecret(24) }, // 192 bits, alcanza y sobra para un password de DB
	"ENCRYPTION_KEY":    func() string { return randomHexSecret(32) }, // 256 bits, ver backend/shared/crypto.py
}

// ensureEnvFile crea .env a partir de .env.example en el primer uso, con
// los secretos de generatedSecretKeys reemplazados por valores
// aleatorios propios de esta instalacion (nunca copia esas lineas tal
// cual). El resto de las variables (URLs, flags de dry-run, etc) se
// copian sin tocar -- no son secretos, y cambiarlas es responsabilidad
// del operador si hace falta.
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

	lines := strings.Split(string(data), "\n")
	generated := make([]string, 0, len(generatedSecretKeys))
	for i, line := range lines {
		for key, gen := range generatedSecretKeys {
			if strings.HasPrefix(line, key+"=") {
				lines[i] = key + "=" + gen()
				generated = append(generated, key)
			}
		}
	}
	out := strings.Join(lines, "\n")

	// 0o600 (no 0o644): .env ya no tiene solo valores de demo, tiene
	// secretos reales generados recien arriba -- no hay motivo para que
	// otros usuarios de la misma maquina puedan leerlo.
	if err := os.WriteFile(envPath, []byte(out), 0o600); err != nil {
		fatal("No se pudo crear .env: %v", err)
	}
	fmt.Println("Primera vez: se creo .env a partir de .env.example, con secretos nuevos")
	fmt.Println("generados al azar para esta instalacion (" + strings.Join(generated, ", ") + ") --")
	fmt.Println("no se reusan entre instalaciones. Ver docs/runbook.md para mas detalle.")
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
