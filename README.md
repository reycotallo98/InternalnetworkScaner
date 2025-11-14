Escaner de red interna automatizado, que a partir de un archivo generado con nmap -oA, ejecuta todo tipo de escaneos y explotación de los servicios.

## Uso

1. Ejecuta un escaneo inicial con salida XML:

   ```bash
   nmap -sS -sV -oA scans/oficina 10.10.0.0/24
   ```

2. Procesa el resultado con el script:

   ```bash
   python internal_network_scanner.py --nmap-base scans/oficina
   ```

   El script analiza `scans/oficina.xml`, identifica los servicios abiertos y, según el perfil de cada servicio (HTTP, SMB, FTP, SSH, etc.), lanza automáticamente comandos adicionales como `whatweb`, `nikto`, `enum4linux` o escaneos específicos de Nmap. Cada salida se almacena en carpetas por host dentro del directorio `reports/` (por ejemplo, `reports/10_10_0_5/`). Además, se generan automáticamente `summary.md` y `commands.csv` con el estado de cada acción para que puedas revisar todo el resultado de un vistazo.

3. Si solo quieres revisar los comandos que se ejecutarían, usa el modo `--dry-run`:

   ```bash
   python internal_network_scanner.py --nmap-base scans/oficina --dry-run
   ```

### Opciones adicionales

- `--output`: carpeta donde guardar los reportes (por defecto `reports`).
- `--max-workers`: número de comandos simultáneos para acelerar la ejecución.
- `--dry-run`: imprime los comandos planeados sin ejecutarlos, útil para ajustar la lista antes de lanzar la enumeración completa.
- Los archivos `summary.md` y `commands.csv` dentro del directorio de salida sirven como un panel de control del escaneo: el primero muestra tablas Markdown con los hosts y comandos ejecutados, mientras que el segundo facilita importar los resultados a una hoja de cálculo.
