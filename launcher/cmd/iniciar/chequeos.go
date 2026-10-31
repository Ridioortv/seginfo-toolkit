package main

// Chequeos antes de instalar: explican en castellano que hacer, sin que haya que leer logs.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	minDiskGB       = 25     // espacio libre minimo para la PRIMERA instalacion / una actualizacion
	warnDiskGB      = 3      // en el arranque diario solo se avisa por debajo de esto
	minRAMGB        = 8      // por debajo: aviso, sigue
	minMapCount     = 262144 // OpenSearch se niega a arrancar con menos
	diskFloodPct    = 95
	diskFullMsgHint = "Si el disco pasa del 95 % OpenSearch deja de guardar logs."
)

// envInt lee un entero de una variable de entorno (para ajustar los minimos o probar); def si no esta o no es numero.
func envInt(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v >= 0 {
		return v
	}
	return def
}

// diskCheck: false + mensaje si hay menos de `need` GB libres.
func diskCheck(freeGB, need int, where string) (bool, string) {
	if freeGB >= need {
		return true, fmt.Sprintf("Espacio en disco: %d GB libres (hacen falta %d GB).", freeGB, need)
	}
	return false, fmt.Sprintf(`No hay lugar suficiente en el disco para instalar TERO Security.
  Hacen falta al menos %d GB libres y hay %d GB (disco: %s).
  Que podes hacer:
    - Vaciar la papelera de reciclaje y borrar archivos o programas que no uses.
    - Limpiar imagenes de Docker viejas (en una terminal): docker system prune -a   (pide confirmacion)
    - Despues volve a abrir TERO Security: retoma desde donde quedo.`, need, freeGB, where)
}

// ramCheck: aviso (no corta) si hay menos de `need` GB.
func ramCheck(gb, need int) (bool, string) {
	if gb >= need {
		return true, fmt.Sprintf("Memoria RAM: %d GB.", gb)
	}
	return false, fmt.Sprintf("Esta PC tiene %d GB de memoria RAM. TERO Security recomienda %d GB o mas: va a andar, pero puede ir lento.\n  Cerra el navegador y otros programas pesados mientras lo uses.", gb, need)
}

// parseMapCount interpreta la salida de `sysctl -n vm.max_map_count`.
func parseMapCount(out string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(out))
	return n, err == nil
}

// ensureMapCount: OpenSearch necesita vm.max_map_count >= 262144 DENTRO de la VM de Docker Desktop
// (WSL2). Es best-effort: si no hay WSL (backend Hyper-V) o no se puede leer, no se dice nada.
func ensureMapCount() {
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("wsl", "-d", "docker-desktop", "-e", "sysctl", "-n", "vm.max_map_count").Output()
	if err != nil {
		return
	}
	n, ok := parseMapCount(string(out))
	if !ok || n >= minMapCount {
		return
	}
	fmt.Printf("vm.max_map_count=%d es muy bajo: OpenSearch (el motor de logs) necesita al menos %d. Lo ajusto...\n", n, minMapCount)
	if exec.Command("wsl", "-d", "docker-desktop", "-e", "sysctl", "-w", fmt.Sprintf("vm.max_map_count=%d", minMapCount)).Run() == nil {
		fmt.Println("Ajustado (vale hasta que se reinicie Docker Desktop; este programa lo vuelve a ajustar cada vez).")
		return
	}
	fmt.Println("No pude ajustarlo solo. Para dejarlo fijo, crea o edita el archivo .wslconfig de tu carpeta de usuario (C:\\Users\\TU_USUARIO\\.wslconfig) con:")
	fmt.Println("    [wsl2]")
	fmt.Printf("    kernelCommandLine = sysctl.vm.max_map_count=%d\n", minMapCount)
	fmt.Println("y despues, en PowerShell:  wsl --shutdown   (y volve a abrir Docker Desktop).")
}

// freeDisks devuelve (GB libres, carpeta) del disco del proyecto y del disco donde Docker Desktop guarda
// sus datos por defecto (%LOCALAPPDATA%): se usa el que tenga MENOS lugar.
func minFreeDisk(projectDir string) (int, string) {
	dirs := []string{projectDir}
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		dirs = append(dirs, d)
	}
	best, bestDir := -1, projectDir
	for _, d := range dirs {
		gb := freeDiskGB(d)
		if gb < 0 {
			continue
		}
		if best < 0 || gb < best {
			best, bestDir = gb, d
		}
	}
	if best < 0 {
		return 0, projectDir
	}
	return best, bestDir
}
