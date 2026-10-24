//go:build !windows

package main

// Pruebas del lanzador con un `docker` y un `zstd` FALSOS (scripts sh en el PATH): no hace falta
// Docker ni internet. Comprueban QUE comandos corre cada caso (el arranque diario no baja ni compila).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecideMode(t *testing.T) {
	cases := []struct {
		name           string
		compile, force bool
		pkg, installed string
		missing        []string
		want           startMode
	}{
		{"primera vez", false, false, "1.0.0", "", nil, modeFirst},
		{"misma version, todo instalado", false, false, "1.0.0", "1.0.0", nil, modeDaily},
		{"version nueva", false, false, "1.1.0", "1.0.0", nil, modeUpdate},
		{"falta una imagen", false, false, "1.0.0", "1.0.0", []string{"x"}, modeMissing},
		{"--actualizar", false, true, "1.0.0", "1.0.0", nil, modeUpdate},
		{"--compilar gana", true, true, "1.0.0", "1.0.0", nil, modeCompile},
	}
	for _, c := range cases {
		if got := decideMode(c.compile, c.force, c.pkg, c.installed, c.missing); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestDiskCheck(t *testing.T) {
	ok, msg := diskCheck(10, 25, `C:\`)
	if ok || !strings.Contains(msg, "25 GB") || !strings.Contains(msg, "10 GB") || !strings.Contains(msg, "docker system prune") {
		t.Fatalf("poco disco: ok=%v msg=%q", ok, msg)
	}
	if ok, _ := diskCheck(25, 25, "x"); !ok {
		t.Fatal("25 GB justos deberian alcanzar")
	}
}

func TestRAMCheck(t *testing.T) {
	if ok, msg := ramCheck(4, 8); ok || !strings.Contains(msg, "4 GB") {
		t.Fatalf("4 GB deberia avisar: %v %q", ok, msg)
	}
	if ok, _ := ramCheck(8, 8); !ok {
		t.Fatal("8 GB no deberia avisar")
	}
}

func TestParseMapCount(t *testing.T) {
	if n, ok := parseMapCount("65530\n"); !ok || n != 65530 {
		t.Fatal("65530")
	}
	if _, ok := parseMapCount("error"); ok {
		t.Fatal("basura no es un numero")
	}
}

func TestTotalRAMRedondeaUnaPCDe8GB(t *testing.T) {
	f := filepath.Join(t.TempDir(), "meminfo")
	_ = os.WriteFile(f, []byte("MemTotal:        8060000 kB\n"), 0o644)
	t.Setenv("TERO_MEMINFO", f)
	if got := totalRAMGB(); got != 8 {
		t.Fatalf("una PC de 8 GB reporta ~7,7 GiB y debe contar como 8, got %d", got)
	}
}

func TestEffectiveVersionYFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TERO_VERSION", "")
	if v := effectiveVersion(dir); v != "local" {
		t.Fatalf("sin VERSION: %s", v)
	}
	_ = os.WriteFile(filepath.Join(dir, "VERSION"), []byte("1.2.3\r\n"), 0o644)
	if v := effectiveVersion(dir); v != "1.2.3" {
		t.Fatalf("VERSION con CRLF: %q", v)
	}
	t.Setenv("TERO_VERSION", "9.9.9")
	if v := effectiveVersion(dir); v != "9.9.9" {
		t.Fatalf("la variable de entorno manda: %s", v)
	}
}

func TestFindOfflineArchive(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tero")
	_ = os.Mkdir(dir, 0o755)
	if findOfflineArchive(dir, "1.0.0") != "" {
		t.Fatal("no hay archivo")
	}
	_ = os.WriteFile(filepath.Join(dir, "tero-imagenes-0.9.0.tar.zst"), []byte("x"), 0o644)
	if findOfflineArchive(dir, "1.0.0") != "" {
		t.Fatal("otra version no se usa")
	}
	up := filepath.Join(root, "tero-imagenes-1.0.0.tar.zst")
	_ = os.WriteFile(up, []byte("x"), 0o644)
	if findOfflineArchive(dir, "1.0.0") != up {
		t.Fatal("tiene que encontrarlo en la carpeta de arriba")
	}
	here := filepath.Join(dir, "tero-imagenes-1.0.0.tar.zst")
	_ = os.WriteFile(here, []byte("x"), 0o644)
	if findOfflineArchive(dir, "1.0.0") != here {
		t.Fatal("el de al lado del programa tiene prioridad")
	}
}

func TestVerifyChecksum(t *testing.T) {
	f := filepath.Join(t.TempDir(), "a.tar.zst")
	_ = os.WriteFile(f, []byte("datos"), 0o644)
	if checked, err := verifyChecksum(f); checked || err != nil {
		t.Fatal("sin .sha256 no se puede verificar y no es error")
	}
	sum := sha256.Sum256([]byte("datos"))
	_ = os.WriteFile(f+".sha256", []byte(hex.EncodeToString(sum[:])+"  a.tar.zst\n"), 0o644)
	if checked, err := verifyChecksum(f); !checked || err != nil {
		t.Fatalf("suma correcta: %v %v", checked, err)
	}
	_ = os.WriteFile(f+".sha256", []byte(strings.Repeat("0", 64)+"  a.tar.zst\n"), 0o644)
	if _, err := verifyChecksum(f); err == nil || !strings.Contains(err.Error(), "danado") {
		t.Fatalf("suma incorrecta debe fallar: %v", err)
	}
}

func TestDevServicesYTandas(t *testing.T) {
	text := "services:\n  tero-base:\n    build: {}\n  auth-service:\n    build: {}\n  scan-service:\n    build: {}\n  remote-agent:\n    build: {}\n  remote-agent-wan:\n    build: {}\n  frontend:\n    build: {}\n"
	got := devServices(text)
	if strings.Join(got, ",") != "auth-service,scan-service,frontend" {
		t.Fatalf("sin base ni agentes: %v", got)
	}
	b := chunk([]string{"a", "b", "c", "d", "e", "f", "g"}, 3)
	if len(b) != 3 || len(b[0]) != 3 || len(b[2]) != 1 {
		t.Fatalf("tandas: %v", b)
	}
}

func TestDevComposeRealTiene17ServiciosConBuild(t *testing.T) {
	data, err := os.ReadFile("../../../docker-compose.dev.yml")
	if err != nil {
		t.Skip("no esta docker-compose.dev.yml")
	}
	if n := len(devServices(string(data))); n != 16 {
		t.Fatalf("esperaba 13 simples + scan + coderepo + frontend = 16, hay %d", n)
	}
}

// --- docker falso ------------------------------------------------------------------------------

type fake struct {
	dir string
	log string
}

// instalarFalsos pone `docker` y `zstd` falsos al frente del PATH. STUB_PULL_RC / STUB_PULL_MSG
// controlan `compose pull`; las imagenes "instaladas" estan en <dir>/instaladas.txt.
func instalarFalsos(t *testing.T) *fake {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	_ = os.Mkdir(bin, 0o755)
	docker := `#!/bin/sh
echo "docker $*" >> "$STUB_DIR/llamadas.log"
case "$1 $2" in
  "compose pull") n=$(cat "$STUB_DIR/pulls" 2>/dev/null || echo 0); echo $((n+1)) > "$STUB_DIR/pulls"
     echo "$STUB_PULL_MSG" >&2; [ "${STUB_PULL_RC:-0}" = "0" ] && cp "$STUB_DIR/imagenes.txt" "$STUB_DIR/instaladas.txt"; exit "${STUB_PULL_RC:-0}";;
  "image inspect") grep -qxF "$3" "$STUB_DIR/instaladas.txt" 2>/dev/null; exit $?;;
  "load "*|"load ") cat > /dev/null; cp "$STUB_DIR/imagenes.txt" "$STUB_DIR/instaladas.txt"; exit 0;;
  "login ghcr.io") cat > "$STUB_DIR/token_recibido"; exit 0;;
esac
case "$*" in
  *"config --images"*) cat "$STUB_DIR/imagenes.txt"; exit 0;;
  *" build "*|*" build") echo "BUILDX=$BUILDX_NO_DEFAULT_ATTESTATIONS PAR=$COMPOSE_PARALLEL_LIMIT" >> "$STUB_DIR/entorno_build.log"; exit "${STUB_BUILD_RC:-0}";;
esac
exit 0
`
	zstd := "#!/bin/sh\necho \"zstd $*\" >> \"$STUB_DIR/llamadas.log\"\ncat \"$2\"\n"
	_ = os.WriteFile(filepath.Join(bin, "docker"), []byte(docker), 0o755)
	_ = os.WriteFile(filepath.Join(bin, "zstd"), []byte(zstd), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "imagenes.txt"), []byte("postgres:16\nghcr.io/x/tero-auth-service:1.0.0\n"), 0o644)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STUB_DIR", dir)
	t.Setenv("STUB_PULL_MSG", "pulling")
	t.Setenv("STUB_PULL_RC", "0")
	retryDelay = 0
	return &fake{dir: dir, log: filepath.Join(dir, "llamadas.log")}
}

func (f *fake) llamadas() string {
	b, _ := os.ReadFile(f.log)
	return string(b)
}

func TestMissingImages(t *testing.T) {
	f := instalarFalsos(t)
	imgs := composeImages()
	if len(imgs) != 2 {
		t.Fatalf("imagenes del compose: %v", imgs)
	}
	if len(missingImages(imgs)) != 2 {
		t.Fatal("al principio faltan las 2")
	}
	_ = os.WriteFile(filepath.Join(f.dir, "instaladas.txt"), []byte("postgres:16\n"), 0o644)
	if m := missingImages(imgs); len(m) != 1 || m[0] != "ghcr.io/x/tero-auth-service:1.0.0" {
		t.Fatalf("falta solo la nuestra: %v", m)
	}
}

func TestPullOK(t *testing.T) {
	f := instalarFalsos(t)
	if pullImages() != pullOK {
		t.Fatal("pull ok")
	}
	if strings.Count(f.llamadas(), "compose pull") != 1 {
		t.Fatal("una sola llamada")
	}
}

func TestPullSinPermisoNoReintenta(t *testing.T) {
	f := instalarFalsos(t)
	t.Setenv("STUB_PULL_RC", "1")
	t.Setenv("STUB_PULL_MSG", "Error response from daemon: unauthorized: authentication required")
	if pullImages() != pullNeedsLogin {
		t.Fatal("tiene que pedir login")
	}
	if strings.Count(f.llamadas(), "compose pull") != 1 {
		t.Fatal("sin permiso no tiene sentido reintentar")
	}
}

func TestPullSinInternetReintenta3Veces(t *testing.T) {
	f := instalarFalsos(t)
	t.Setenv("STUB_PULL_RC", "1")
	t.Setenv("STUB_PULL_MSG", "dial tcp: lookup ghcr.io: no such host")
	if pullImages() != pullFailed {
		t.Fatal("tiene que fallar")
	}
	if strings.Count(f.llamadas(), "compose pull") != 3 {
		t.Fatalf("3 intentos, hubo: %s", f.llamadas())
	}
}

func TestLoginAutomaticoSinImprimirElToken(t *testing.T) {
	f := instalarFalsos(t)
	t.Setenv("TERO_GHCR_USUARIO", "cliente1")
	t.Setenv("TERO_GHCR_TOKEN", "ghp_SECRETO")
	loginGHCRIfConfigured(t.TempDir())
	if !strings.Contains(f.llamadas(), "docker login ghcr.io -u cliente1 --password-stdin") {
		t.Fatalf("login: %s", f.llamadas())
	}
	if strings.Contains(f.llamadas(), "ghp_SECRETO") {
		t.Fatal("el token no puede ir en los argumentos")
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, "token_recibido")); string(b) != "ghp_SECRETO" {
		t.Fatalf("el token va por stdin: %q", b)
	}
}

func TestLoadOfflineConZstd(t *testing.T) {
	f := instalarFalsos(t)
	archivo := filepath.Join(t.TempDir(), "tero-imagenes-1.0.0.tar.zst")
	_ = os.WriteFile(archivo, []byte("fake"), 0o644)
	if err := loadOfflineArchive(archivo); err != nil {
		t.Fatal(err)
	}
	l := f.llamadas()
	if !strings.Contains(l, "zstd -dc") || !strings.Contains(l, "docker load") {
		t.Fatalf("zstd -dc | docker load: %s", l)
	}
	if strings.Contains(l, "compose pull") {
		t.Fatal("no debe bajar nada")
	}
}

func TestLoadOfflineDanadoNoSeCarga(t *testing.T) {
	f := instalarFalsos(t)
	archivo := filepath.Join(t.TempDir(), "tero-imagenes-1.0.0.tar.zst")
	_ = os.WriteFile(archivo, []byte("datos"), 0o644)
	_ = os.WriteFile(archivo+".sha256", []byte(strings.Repeat("0", 64)+"  x\n"), 0o644)
	if err := loadOfflineArchive(archivo); err == nil {
		t.Fatal("tiene que fallar")
	}
	if strings.Contains(f.llamadas(), "docker load") {
		t.Fatal("no se carga un archivo danado")
	}
}

func TestCompileInBatches(t *testing.T) {
	f := instalarFalsos(t)
	work := t.TempDir()
	_ = os.WriteFile(filepath.Join(work, "docker-compose.dev.yml"),
		[]byte("services:\n  tero-base:\n    build: {}\n  a-service:\n    build: {}\n  b-service:\n    build: {}\n  c-service:\n    build: {}\n  d-service:\n    build: {}\n  remote-agent:\n    build: {}\n"), 0o644)
	old, _ := os.Getwd()
	_ = os.Chdir(work)
	defer os.Chdir(old)
	t.Setenv("COMPOSE_PARALLEL_LIMIT", "")
	if err := compileInBatches(); err != nil {
		t.Fatal(err)
	}
	var builds []string
	for _, l := range strings.Split(f.llamadas(), "\n") {
		if strings.Contains(l, " build ") {
			builds = append(builds, l)
		}
	}
	if len(builds) != 3 { // base + 2 tandas (3 + 1)
		t.Fatalf("base + 2 tandas, hubo %d: %v", len(builds), builds)
	}
	if !strings.Contains(builds[0], "--profile build build tero-base") {
		t.Fatalf("primero la base: %s", builds[0])
	}
	if !strings.HasSuffix(builds[1], "build a-service b-service c-service") || !strings.HasSuffix(builds[2], "build d-service") {
		t.Fatalf("tandas de 3: %v", builds[1:])
	}
	env, _ := os.ReadFile(filepath.Join(f.dir, "entorno_build.log"))
	if !strings.Contains(string(env), "BUILDX=1") || !strings.Contains(string(env), "PAR=3") {
		t.Fatalf("entorno de build: %s", env)
	}
}

func TestCompileFallaSiUnaTandaFalla(t *testing.T) {
	instalarFalsos(t)
	t.Setenv("STUB_BUILD_RC", "1")
	work := t.TempDir()
	_ = os.WriteFile(filepath.Join(work, "docker-compose.dev.yml"), []byte("services:\n  a-service:\n    build: {}\n"), 0o644)
	old, _ := os.Getwd()
	_ = os.Chdir(work)
	defer os.Chdir(old)
	if compileInBatches() == nil {
		t.Fatal("tiene que fallar")
	}
}

func TestCanCompileHereSoloConCodigoFuente(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	_ = os.Chdir(dir)
	if canCompileHere() {
		t.Fatal("sin docker-compose.dev.yml no se puede compilar")
	}
	_ = os.WriteFile(filepath.Join(dir, "docker-compose.dev.yml"), []byte("services: {}\n"), 0o644)
	if !canCompileHere() {
		t.Fatal("con docker-compose.dev.yml si se puede compilar")
	}
}
