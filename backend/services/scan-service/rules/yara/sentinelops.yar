/*
 * Reglas YARA 100% AUTORADAS por SentinelOps.
 *
 * YARA (el motor, BSD-3-Clause) se invoca como binario externo via
 * subprocess (ver app/scanners/yara.py), nunca linkeado -- igual que
 * el resto de los escaneres de esta plataforma. Pero las REGLAS que
 * corre importan tanto como el motor: muchos "rule packs" de YARA
 * publicados por terceros (ej. el proyecto "Yara-Rules" en GitHub)
 * mezclan licencias distintas rule por rule, algunas con terminos de
 * uso no comercial o atribucion no resuelta -- en vez de auditar cada
 * regla de un pack ajeno, SentinelOps escribe y mantiene las propias.
 * Alcance deliberadamente generico (indicadores de patrones de riesgo
 * conocidos, no firmas de familias de malware puntuales) para no
 * necesitar actualizarlas constantemente como un antivirus comercial.
 *
 * SOLO DETECCION: estas reglas nunca ejecutan ni modifican el archivo
 * que analizan, solo inspeccionan su contenido como texto/bytes.
 */

rule SentinelOps_EICAR_Test_File
{
    meta:
        author = "SentinelOps"
        description = "Archivo de prueba EICAR estandar de la industria -- confirma que el motor de deteccion esta funcionando end-to-end, no indica malware real."
        severity = "info"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule SentinelOps_PHP_Obfuscated_Webshell_Pattern
{
    meta:
        author = "SentinelOps"
        description = "Patron tipico de webshell PHP: ejecucion de codigo reconstruido via base64/gzip/rot13 a partir de un parametro de request HTTP ($_POST/$_GET/$_REQUEST)."
        severity = "critical"
    strings:
        $eval1 = "eval(base64_decode(" nocase
        $eval2 = "eval(gzinflate(" nocase
        $eval3 = "eval(str_rot13(" nocase
        $assert_eval = "assert(base64_decode(" nocase
        $superglobal1 = "$_POST["
        $superglobal2 = "$_GET["
        $superglobal3 = "$_REQUEST["
    condition:
        (any of ($eval1, $eval2, $eval3, $assert_eval)) and (any of ($superglobal1, $superglobal2, $superglobal3))
}

rule SentinelOps_Embedded_PE_In_NonExecutable
{
    meta:
        author = "SentinelOps"
        description = "Cabecera MZ/PE (ejecutable de Windows) encontrada dentro de un archivo, posiblemente un dropper/payload embebido en un documento o recurso que no deberia contener codigo ejecutable."
        severity = "high"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $pe_marker = "This program cannot be run in DOS mode"
    condition:
        $mz and $pe_marker
}

rule SentinelOps_Suspicious_Obfuscated_PowerShell
{
    meta:
        author = "SentinelOps"
        description = "Patron de PowerShell ofuscado/encoded tipico de payloads de post-explotacion: ejecucion dinamica (IEX) de contenido decodificado desde Base64, a menudo combinado con flags para ocultar la ventana o saltear la politica de ejecucion."
        severity = "high"
    strings:
        $iex = "IEX" nocase
        $invoke_expr = "Invoke-Expression" nocase
        $frombase64 = "FromBase64String" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $enc = "-EncodedCommand" nocase
    condition:
        (any of ($iex, $invoke_expr)) and $frombase64
        or
        (any of ($hidden, $bypass, $enc)) and (any of ($iex, $invoke_expr, $frombase64))
}

rule SentinelOps_Python_Reverse_Shell_Oneliner
{
    meta:
        author = "SentinelOps"
        description = "Patron de 'reverse shell' de una linea en Python: combinacion de socket + subprocess/os.system + duplicacion de descriptores (dup2), tipica de post-explotacion para abrir una shell interactiva hacia un host remoto."
        severity = "critical"
    strings:
        $socket = "socket.socket(" nocase
        $dup2 = "dup2(" nocase
        $subprocess = "subprocess.call" nocase
        $os_system = "os.system(" nocase
        $pty_spawn = "pty.spawn(" nocase
    condition:
        $socket and $dup2 and (any of ($subprocess, $os_system, $pty_spawn))
}
