// TERO Security - Restablecer contrasena.exe
//
// Genera el link para elegir una contrasena nueva SIN depender del mail: pide el email de la
// cuenta, le pregunta al servicio de autenticacion (que ya esta corriendo) y muestra un link de
// un solo uso que vale 30 minutos. Sirve cuando no hay SMTP configurado o cuando la persona
// administradora olvido su propia clave. Hace falta tener la plataforma iniciada.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	fmt.Println("========================================")
	fmt.Println(" TERO Security - restablecer contrasena")
	fmt.Println("========================================")
	fmt.Println()

	exePath, err := os.Executable()
	if err != nil {
		fatal("No se pudo determinar la ubicacion del programa: %v", err)
	}
	dir := filepath.Dir(exePath)
	if err := os.Chdir(dir); err != nil {
		fatal("No se pudo entrar a la carpeta del proyecto: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		fatal("No se encontro Docker. Abri Docker Desktop y volve a ejecutar este programa.")
	}
	// Mismo criterio que "Iniciar": la version de las imagenes llega a docker-compose.yml por TERO_VERSION.
	if os.Getenv("TERO_VERSION") == "" {
		v := "local"
		if raw, err := os.ReadFile(filepath.Join(dir, "VERSION")); err == nil && strings.TrimSpace(string(raw)) != "" {
			v = strings.TrimSpace(string(raw))
		}
		_ = os.Setenv("TERO_VERSION", v)
	}

	email := ""
	if len(os.Args) > 1 {
		email = strings.TrimSpace(os.Args[1])
	}
	if email == "" {
		fmt.Print("Email de la cuenta que olvido la contrasena: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		email = strings.TrimSpace(line)
	}
	if email == "" {
		fatal("Falta el email.")
	}

	cmd := exec.Command("docker", "compose", "exec", "-T", "auth-service", "python", "-m", "app.cli_password", email)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println()
		fmt.Println("No se pudo generar el link. Revisa que la plataforma este iniciada")
		fmt.Println("(\"TERO Security - Iniciar.exe\") y que el email sea el de una cuenta con contrasena.")
		pause()
		os.Exit(1)
	}
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
