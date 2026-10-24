package main

// Imagenes de Docker: de donde salen (registro privado GHCR, archivo offline o compilacion local),
// cuando hace falta conseguirlas y cuando NO (arranque de todos los dias).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const installedVersionFile = ".tero-version-instalada"

// startMode dice que hay que hacer con las imagenes en este arranque.
type startMode string

const (
	modeFirst   startMode = "primera"    // nunca se instalo
	modeUpdate  startMode = "actualizar" // cambio la version (o se pidio --actualizar)
	modeMissing startMode = "faltan"     // misma version, pero falta alguna imagen en la PC
	modeCompile startMode = "compilar"   // --compilar
	modeDaily   startMode = "diario"     // todo instalado: solo `docker compose up -d`
)

// decideMode: el arranque diario NO baja ni compila nada. Solo se consiguen imagenes la primera
// vez, cuando cambia la version, cuando falta alguna imagen o cuando se pide a mano.
func decideMode(compile, force bool, packageVersion, installedVersion string, missing []string) startMode {
	switch {
	case compile:
		return modeCompile
	case force:
		return modeUpdate
	case installedVersion == "":
		return modeFirst
	case installedVersion != packageVersion:
		return modeUpdate
	case len(missing) > 0:
		return modeMissing
	}
	return modeDaily
}

// readTrimmed lee un archivo de una linea (VERSION, .tero-version-instalada). "" si no existe.
func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// effectiveVersion: TERO_VERSION del entorno si esta definida; si no, el archivo VERSION; si no, "local".
func effectiveVersion(dir string) string {
	if v := strings.TrimSpace(os.Getenv("TERO_VERSION")); v != "" {
		return v
	}
	if v := readTrimmed(filepath.Join(dir, "VERSION")); v != "" {
		return v
	}
	return "local"
}

// dockerCmd arma un comando de docker; los tests lo reemplazan por un docker falso (PATH).
var dockerCmd = func(args ...string) *exec.Cmd { return exec.Command("docker", args...) }

// composeImages: las imagenes que pide el compose con la version actual.
func composeImages(extraFiles ...string) []string {
	args := []string{"compose"}
	for _, f := range extraFiles {
		args = append(args, "-f", f)
	}
	args = append(args, "config", "--images")
	out, err := dockerCmd(args...).Output()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			set[l] = true
		}
	}
	list := make([]string, 0, len(set))
	for l := range set {
		list = append(list, l)
	}
	sort.Strings(list)
	return list
}

// missingImages: las que NO estan en esta PC.
func missingImages(images []string) []string {
	var missing []string
	for _, img := range images {
		if dockerCmd("image", "inspect", img).Run() != nil {
			missing = append(missing, img)
		}
	}
	return missing
}

// --- Instalacion sin internet -------------------------------------------------------------------

// findOfflineArchive busca tero-imagenes-<version>.tar.zst junto al instalador o en la carpeta de arriba.
func findOfflineArchive(dir, version string) string {
	name := "tero-imagenes-" + version + ".tar.zst"
	for _, candidate := range []string{filepath.Join(dir, name), filepath.Join(filepath.Dir(dir), name)} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return ""
}

// verifyChecksum compara el archivo con su .sha256 (formato de sha256sum: "<hash>  <nombre>").
// Si no hay .sha256 no se puede verificar y devuelve (false, nil).
func verifyChecksum(path string) (checked bool, err error) {
	raw, readErr := os.ReadFile(path + ".sha256")
	if readErr != nil {
		return false, nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return true, fmt.Errorf("el archivo %s.sha256 esta vacio", filepath.Base(path))
	}
	f, openErr := os.Open(path)
	if openErr != nil {
		return true, openErr
	}
	defer f.Close()
	h := sha256.New()
	if _, copyErr := io.Copy(h, f); copyErr != nil {
		return true, copyErr
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), fields[0]) {
		return true, fmt.Errorf("%s no coincide con su suma de verificacion: se copio incompleto o danado, volve a copiarlo", filepath.Base(path))
	}
	return true, nil
}

// loadOfflineArchive: `zstd -dc archivo | docker load` (o `docker load -i` si no hay zstd instalado).
func loadOfflineArchive(path string) error {
	checked, err := verifyChecksum(path)
	if err != nil {
		return err
	}
	if checked {
		fmt.Println("El archivo offline esta completo (suma de verificacion correcta).")
	}
	fmt.Printf("Cargando las imagenes desde %s (no usa internet; tarda unos minutos)...\n", filepath.Base(path))

	zstd, lookErr := exec.LookPath("zstd")
	if lookErr != nil {
		// Los Docker nuevos leen .zst directamente; si el tuyo no, se explica que hacer.
		cmd := dockerCmd("load", "-i", path)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			return fmt.Errorf("no pude cargar %s. Instala zstd (https://github.com/facebook/zstd/releases) y volve a intentar: %v", filepath.Base(path), runErr)
		}
		return nil
	}
	dec := exec.Command(zstd, "-dc", path)
	load := dockerCmd("load")
	pipe, pipeErr := dec.StdoutPipe()
	if pipeErr != nil {
		return pipeErr
	}
	load.Stdin = pipe
	load.Stdout, load.Stderr = os.Stdout, os.Stderr
	if err := load.Start(); err != nil {
		return err
	}
	if err := dec.Start(); err != nil {
		_ = load.Process.Kill()
		return err
	}
	decErr := dec.Wait()
	loadErr := load.Wait()
	if decErr != nil || loadErr != nil {
		return fmt.Errorf("no pude cargar las imagenes de %s (archivo incompleto o danado). Volve a copiarlo", filepath.Base(path))
	}
	return nil
}

// --- Bajar de GHCR (registro privado) -------------------------------------------------------------

var authErrorRe = regexp.MustCompile(`(?i)unauthorized|denied|authentication required|requires authentication|no basic auth`)

type pullResult int

const (
	pullOK pullResult = iota
	pullNeedsLogin
	pullFailed
)

// retryDelay: pausa entre intentos de descarga (los tests la ponen en 0).
var retryDelay = 10 * time.Second

// pullImages corre `docker compose pull` hasta 3 veces. Un error de permisos no se reintenta.
func pullImages() pullResult {
	for attempt := 1; attempt <= 3; attempt++ {
		var buf bytes.Buffer
		cmd := dockerCmd("compose", "pull")
		cmd.Env = append(os.Environ(), "COMPOSE_PARALLEL_LIMIT=4")
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
		if cmd.Run() == nil {
			return pullOK
		}
		if authErrorRe.MatchString(buf.String()) {
			return pullNeedsLogin
		}
		fmt.Printf("\nNo pude bajar las imagenes (intento %d de 3). Reintento en %d segundos...\n", attempt, int(retryDelay.Seconds()))
		time.Sleep(retryDelay)
	}
	return pullFailed
}

// loginGHCRIfConfigured inicia sesion si hay TERO_GHCR_USUARIO/TERO_GHCR_TOKEN o un archivo
// .ghcr-login (usuario en la 1a linea, token en la 2a). El token nunca se imprime.
func loginGHCRIfConfigured(dir string) {
	user, token := strings.TrimSpace(os.Getenv("TERO_GHCR_USUARIO")), strings.TrimSpace(os.Getenv("TERO_GHCR_TOKEN"))
	if token == "" {
		if f, err := os.Open(filepath.Join(dir, ".ghcr-login")); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			if sc.Scan() {
				user = strings.TrimSpace(sc.Text())
			}
			if sc.Scan() {
				token = strings.TrimSpace(sc.Text())
			}
		}
	}
	if user == "" || token == "" {
		return
	}
	cmd := dockerCmd("login", "ghcr.io", "-u", user, "--password-stdin")
	cmd.Stdin = strings.NewReader(token)
	if cmd.Run() == nil {
		fmt.Printf("Sesion iniciada en ghcr.io como %s.\n", user)
	} else {
		fmt.Println("Aviso: no pude iniciar sesion en ghcr.io con el usuario/token guardado.")
	}
}

func explainLogin(version string) {
	fmt.Println()
	fmt.Println("No tengo permiso para bajar las imagenes (el registro es privado).")
	fmt.Println("Inicia sesion UNA vez con el usuario y el token de solo lectura que te dio TERO,")
	fmt.Println("abriendo una terminal (PowerShell) y corriendo:")
	fmt.Println("    echo TU_TOKEN | docker login ghcr.io -u TU_USUARIO --password-stdin")
	fmt.Printf("y volve a abrir este programa. Sin internet: copia el archivo tero-imagenes-%s.tar.zst\n", version)
	fmt.Println("junto a este programa y se usa solo.")
}

// --- Compilar en la PC, en tandas (punto 6) ---------------------------------------------------------

var devServiceRe = regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):\s*$`)

// devServices: los servicios con build: de docker-compose.dev.yml, sin la imagen base (va aparte) ni
// los agentes remotos (reusan la imagen de scan-service).
func devServices(devComposeText string) []string {
	var list []string
	for _, m := range devServiceRe.FindAllStringSubmatch(devComposeText, -1) {
		switch m[1] {
		case "tero-base", "remote-agent", "remote-agent-wan":
		default:
			list = append(list, m[1])
		}
	}
	return list
}

func chunk(list []string, size int) [][]string {
	if size < 1 {
		size = 1
	}
	var out [][]string
	for i := 0; i < len(list); i += size {
		end := i + size
		if end > len(list) {
			end = len(list)
		}
		out = append(out, list[i:end])
	}
	return out
}

// canCompileHere: true si esta carpeta trae el codigo fuente (docker-compose.dev.yml), o sea que
// las imagenes se pueden compilar en esta PC cuando no se pueden bajar.
func canCompileHere() bool {
	st, err := os.Stat("docker-compose.dev.yml")
	return err == nil && !st.IsDir()
}

// compileInBatches: compilar las 17 imagenes a la vez agota RAM y disco de una PC chica. Va de a 3
// y sin las "attestations" (SBOM) de BuildKit, que tardaban minutos por imagen.
func compileInBatches() error {
	text, err := os.ReadFile("docker-compose.dev.yml")
	if err != nil {
		return fmt.Errorf("falta docker-compose.dev.yml: no se puede compilar")
	}
	_ = os.Setenv("BUILDX_NO_DEFAULT_ATTESTATIONS", "1")
	if os.Getenv("COMPOSE_PARALLEL_LIMIT") == "" {
		_ = os.Setenv("COMPOSE_PARALLEL_LIMIT", "3")
	}
	// --profile build en TODAS las llamadas: tero-base vive en ese profile y, si no esta activo,
	// Compose rechaza los servicios que lo usan como contexto ("declares unknown service tero-base").
	files := []string{"compose", "-f", "docker-compose.yml", "-f", "docker-compose.dev.yml", "--profile", "build"}
	run := func(extra ...string) error {
		cmd := dockerCmd(append(append([]string{}, files...), extra...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	fmt.Println("Compilando la imagen base comun...")
	if err := run("build", "tero-base"); err != nil {
		return err
	}
	batches := chunk(devServices(string(text)), 3)
	for i, b := range batches {
		fmt.Printf("\nCompilando (tanda %d de %d): %s\n", i+1, len(batches), strings.Join(b, " "))
		if err := run(append([]string{"build"}, b...)...); err != nil {
			return err
		}
	}
	return nil
}
