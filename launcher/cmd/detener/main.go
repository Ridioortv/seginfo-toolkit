// SentinelOps - Detener.exe
//
// Para toda la plataforma (docker compose down) sin borrar los datos
// (los volumenes, como el de Postgres, se conservan).
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	fmt.Println("========================================")
	fmt.Println(" SentinelOps - deteniendo la plataforma")
	fmt.Println("========================================")
	fmt.Println()

	exePath, err := os.Executable()
	if err != nil {
		fatal("No se pudo determinar la ubicacion del programa: %v", err)
	}
	projectDir := filepath.Dir(exePath)

	if err := os.Chdir(projectDir); err != nil {
		fatal("No se pudo entrar a la carpeta del proyecto: %v", err)
	}

	cmd := exec.Command("docker", "compose", "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("\n'docker compose down' fallo: %v", err)
	}

	fmt.Println()
	fmt.Println("Listo. Los datos (base de datos, etc.) se conservan para la proxima vez.")
	pause()
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
