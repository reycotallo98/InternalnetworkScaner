"""Internal network automation helper.

This script ingests an ``nmap -oA`` output (the XML file is required) and
launches a curated set of follow-up enumeration commands depending on the
identified services.  The goal is to reduce the manual effort that usually
follows an initial discovery scan in internal engagements.

Example
-------
    python internal_network_scanner.py --nmap-base scans/internal

The command above expects files such as ``scans/internal.xml`` that were
generated with ``nmap -oA scans/internal <targets>``.
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Sequence


# ------------------------------ Data models ------------------------------


@dataclass(slots=True)
class Service:
    host_ip: str
    port: int
    protocol: str
    service: str
    product: str | None


@dataclass(slots=True)
class Host:
    ip: str
    hostname: str | None
    services: List[Service]


CommandTemplate = Sequence[str]


@dataclass(slots=True)
class ServiceProfile:
    name: str
    matcher: Callable[[Service], bool]
    commands: List[tuple[str, CommandTemplate]]


@dataclass(slots=True)
class PlannedCommand:
    host_ip: str
    service: str
    port: int | None
    description: str
    command: List[str]
    log_path: Path | None = None
    status: str = "pendiente"


# ------------------------------ Parsing logic ------------------------------


def parse_nmap_xml(xml_path: Path) -> List[Host]:
    """Return the list of live hosts extracted from an Nmap XML file."""

    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts: List[Host] = []

    for host in root.findall("host"):
        if host.find("status").attrib.get("state") != "up":
            continue

        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue

        ip = addr.attrib["addr"]
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.attrib.get("name") if hostname_el is not None else None

        services: List[Service] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if not state or state.attrib.get("state") != "open":
                continue

            service_el = port.find("service")
            service_name = service_el.attrib.get("name", "unknown") if service_el else "unknown"
            product = service_el.attrib.get("product") if service_el else None

            services.append(
                Service(
                    host_ip=ip,
                    port=int(port.attrib["portid"]),
                    protocol=port.attrib.get("protocol", "tcp"),
                    service=service_name,
                    product=product,
                )
            )

        if services:
            hosts.append(Host(ip=ip, hostname=hostname, services=services))

    return hosts


# ------------------------------ Command planning ------------------------------


def _cmd(*args: str) -> CommandTemplate:
    return list(args)


def build_service_profiles() -> List[ServiceProfile]:
    return [
        ServiceProfile(
            name="http",
            matcher=lambda s: s.service.startswith("http") or s.port in {80, 443, 8080, 8443},
            commands=[
                ("Fingerprint web (whatweb)", _cmd("whatweb", "{host}")),
                ("Nmap específico HTTP", _cmd("nmap", "-sC", "-sV", "-p", "{port}", "{host}")),
                ("Nikto básico", _cmd("nikto", "-host", "{host}:{port}")),
            ],
        ),
        ServiceProfile(
            name="smb",
            matcher=lambda s: s.service in {"microsoft-ds", "netbios-ssn", "smb"} or s.port in {139, 445},
            commands=[
                ("Enum4linux", _cmd("enum4linux", "-a", "{host}")),
                ("SMBMap", _cmd("smbmap", "-H", "{host}")),
                (
                    "Nmap scripts SMB",
                    _cmd("nmap", "--script", "smb-enum-shares,smb-enum-users", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="ftp",
            matcher=lambda s: s.service == "ftp" or s.port == 21,
            commands=[
                (
                    "FTP anon & brute",
                    _cmd("nmap", "--script", "ftp-anon,ftp-brute", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="ssh",
            matcher=lambda s: s.service == "ssh" or s.port == 22,
            commands=[
                (
                    "SSH hostkeys",
                    _cmd("nmap", "--script", "ssh-auth-methods,ssh-hostkey", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="rdp",
            matcher=lambda s: s.service in {"ms-wbt-server", "rdp"} or s.port == 3389,
            commands=[
                (
                    "RDP enum encryption",
                    _cmd("nmap", "--script", "rdp-enum-encryption", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="database",
            matcher=lambda s: s.service in {"mysql", "mssql", "postgresql"} or s.port in {1433, 3306, 5432},
            commands=[
                ("MySQL info", _cmd("nmap", "--script", "mysql-info", "-p", "{port}", "{host}")),
            ],
        ),
    ]


def plan_commands(hosts: Iterable[Host]) -> List[PlannedCommand]:
    profiles = build_service_profiles()
    commands: List[PlannedCommand] = []

    for host in hosts:
        host_ports = ",".join(str(s.port) for s in host.services)
        commands.append(
            PlannedCommand(
                host_ip=host.ip,
                service="multipuerto",
                port=None,
                description="Nmap detallado de todos los puertos abiertos",
                command=["nmap", "-sC", "-sV", "-p", host_ports, host.ip],
            )
        )

        for service in host.services:
            for profile in profiles:
                if profile.matcher(service):
                    for description, template in profile.commands:
                        commands.append(
                            PlannedCommand(
                                host_ip=service.host_ip,
                                service=profile.name,
                                port=service.port,
                                description=description,
                                command=[arg.format(host=service.host_ip, port=service.port) for arg in template],
                            )
                        )

    return commands


# ------------------------------ Execution helpers ------------------------------


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "comando"


def prepare_log_paths(commands: List[PlannedCommand], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for idx, cmd in enumerate(commands, start=1):
        host_dir = output_dir / cmd.host_ip.replace(".", "_")
        host_dir.mkdir(parents=True, exist_ok=True)
        slug = _slugify(f"{cmd.description}-{cmd.command[0]}")
        cmd.log_path = host_dir / f"{idx:03d}_{slug}.log"


def run_command(cmd: PlannedCommand, dry_run: bool = False) -> None:
    if cmd.log_path is None:
        raise ValueError("El comando planificado no tiene ruta de log asignada")

    header = f"{cmd.host_ip}:{cmd.port or '-'} | {cmd.description}"

    if dry_run:
        cmd.log_path.write_text("DRY RUN\n" + " ".join(cmd.command))
        cmd.status = "simulado"
        print(f"[DRY-RUN] {header}")
        return

    if not shutil.which(cmd.command[0]):
        cmd.log_path.write_text(f"Comando '{cmd.command[0]}' no disponible en el sistema.\n")
        cmd.status = "saltado (binario ausente)"
        print(f"[SKIP] {header}")
        return

    print(f"[RUN] {header}")
    result = subprocess.run(cmd.command, capture_output=True, text=True)
    cmd.log_path.write_text(
        "Comando: " + " ".join(cmd.command) + "\n" * 2 + result.stdout + "\n" + result.stderr
    )
    cmd.status = "ok" if result.returncode == 0 else f"error ({result.returncode})"


def execute_commands(commands: Iterable[PlannedCommand], dry_run: bool, max_workers: int) -> None:
    semaphore = threading.Semaphore(max_workers)

    def worker(cmd: PlannedCommand) -> None:
        with semaphore:
            run_command(cmd, dry_run=dry_run)

    threads: List[threading.Thread] = []
    for command in commands:
        thread = threading.Thread(target=worker, args=(command,), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def write_summary_files(hosts: Iterable[Host], commands: List[PlannedCommand], output_dir: Path) -> None:
    summary_lines = ["# Resumen del escaneo", "", "## Hosts detectados", "", "| Host | Hostname | Servicios |", "| --- | --- | --- |"]
    for host in hosts:
        services = ", ".join(f"{svc.port}/{svc.service}" for svc in host.services) or "-"
        summary_lines.append(f"| {host.ip} | {host.hostname or '-'} | {services} |")

    summary_lines.extend(["", "## Comandos ejecutados", "", "| # | Host | Servicio | Puerto | Descripción | Estado | Log |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for idx, cmd in enumerate(commands, start=1):
        log_rel = cmd.log_path.relative_to(output_dir) if cmd.log_path else Path("-")
        summary_lines.append(
            "| {idx} | {host} | {service} | {port} | {desc} | {status} | {log} |".format(
                idx=idx,
                host=cmd.host_ip,
                service=cmd.service,
                port=cmd.port or "-",
                desc=cmd.description,
                status=cmd.status,
                log=log_rel.as_posix(),
            )
        )

    (output_dir / "summary.md").write_text("\n".join(summary_lines), encoding="utf-8")

    csv_path = output_dir / "commands.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["id", "host", "servicio", "puerto", "descripcion", "estado", "comando", "log"])
        for idx, cmd in enumerate(commands, start=1):
            log_rel = cmd.log_path.relative_to(output_dir) if cmd.log_path else Path("-")
            writer.writerow(
                [
                    idx,
                    cmd.host_ip,
                    cmd.service,
                    cmd.port or "",
                    cmd.description,
                    cmd.status,
                    " ".join(cmd.command),
                    log_rel.as_posix(),
                ]
            )


# ------------------------------ CLI ------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automatiza enumeraciones tras un escaneo Nmap -oA")
    parser.add_argument("--nmap-base", required=True, help="Ruta base utilizada al ejecutar 'nmap -oA'")
    parser.add_argument("--output", default="reports", help="Directorio donde se guardarán los resultados")
    parser.add_argument("--max-workers", type=int, default=4, help="Número máximo de comandos simultáneos")
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar los comandos que se ejecutarían")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    base = Path(args.nmap_base)
    xml_path = base.with_suffix(".xml") if base.suffix != ".xml" else base

    if not xml_path.exists():
        raise SystemExit(f"No se encontró el archivo XML: {xml_path}")

    hosts = parse_nmap_xml(xml_path)
    if not hosts:
        raise SystemExit("No se encontraron hosts activos en el XML proporcionado")

    commands = plan_commands(hosts)
    output_dir = Path(args.output)
    prepare_log_paths(commands, output_dir)
    execute_commands(commands, args.dry_run, args.max_workers)
    write_summary_files(hosts, commands, output_dir)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
