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
from typing import Callable, Iterable, List, Sequence, Set


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


@dataclass(slots=True)
class ADCredentials:
    username: str | None = None
    password: str | None = None
    domain: str | None = None


@dataclass(slots=True)
class OptionalArgument:
    """Argumento que solo se incluye si la clave indicada tiene valor."""

    key: str
    parts: Sequence[str]


CommandElement = str | OptionalArgument
CommandTemplate = Sequence[CommandElement]


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
            state_value = state.attrib.get("state", "").lower() if state is not None else ""
            if not state_value.startswith("open"):
                continue

            service_el = port.find("service")
            if service_el is not None:
                service_name = service_el.attrib.get("name", "unknown")
                product = service_el.attrib.get("product")
            else:
                service_name = "unknown"
                product = None

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


def optional_arg(key: str, *parts: str) -> OptionalArgument:
    return OptionalArgument(key=key, parts=list(parts))


def _cmd(*args: CommandElement) -> CommandTemplate:
    return list(args)


def _format_command(
    template: CommandTemplate,
    context: dict[str, str],
    provided_flags: dict[str, bool],
) -> List[str]:
    command: List[str] = []
    for element in template:
        if isinstance(element, OptionalArgument):
            if provided_flags.get(element.key):
                for part in element.parts:
                    command.append(part.format(**context))
        else:
            command.append(element.format(**context))
    return command


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
                (
                    "SMBMap",
                    _cmd(
                        "smbmap",
                        "-H",
                        "{host}",
                        optional_arg("ad_user", "-u", "{ad_user}"),
                        optional_arg("ad_password", "-p", "{ad_password}"),
                        optional_arg("ad_domain", "-d", "{ad_domain}"),
                    ),
                ),
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
        ServiceProfile(
            name="dns",
            matcher=lambda s: s.service in {"domain", "dns"} or s.port == 53,
            commands=[
                (
                    "Nmap DNS bruteforce",
                    _cmd("nmap", "-sU", "-p", "{port}", "--script", "dns-brute,dns-recursion", "{host}"),
                ),
                ("Consulta version.bind", _cmd("dig", "@{host}", "version.bind", "chaos", "txt")),
            ],
        ),
        ServiceProfile(
            name="smtp",
            matcher=lambda s: s.service in {"smtp", "submission"} or s.port in {25, 587},
            commands=[
                (
                    "SMTP enum usuarios",
                    _cmd("smtp-user-enum", "-M", "VRFY", "-U", "/usr/share/wordlists/smtp_users.txt", "-t", "{host}"),
                ),
                (
                    "SMTP nmap scripts",
                    _cmd("nmap", "--script", "smtp-enum-users,smtp-commands", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="pop3-imap",
            matcher=lambda s: s.service in {"pop3", "pop3s", "imap", "imaps"} or s.port in {110, 995, 143, 993},
            commands=[
                (
                    "POP3/IMAP capabilities",
                    _cmd("nmap", "--script", "pop3-capabilities,imap-capabilities", "-p", "{port}", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="snmp",
            matcher=lambda s: s.service == "snmp" or s.port in {161, 162},
            commands=[
                ("SNMP walk comunitaria pública", _cmd("snmpwalk", "-v2c", "-c", "public", "{host}", "1.3.6.1.2.1.1")),
                (
                    "SNMP nmap", _cmd("nmap", "-sU", "-p", "{port}", "--script", "snmp-info,snmp-brute", "{host}"),
                ),
            ],
        ),
        ServiceProfile(
            name="winrm",
            matcher=lambda s: s.service in {"winrm"} or s.port in {5985, 5986},
            commands=[
                (
                    "WinRM identificación",
                    _cmd(
                        "crackmapexec",
                        "winrm",
                        "{host}",
                        optional_arg("ad_user", "-u", "{ad_user}"),
                        optional_arg("ad_password", "-p", "{ad_password}"),
                        optional_arg("ad_domain", "-d", "{ad_domain}"),
                    ),
                ),
            ],
        ),
    ]


def _normalize_filter_values(values: Sequence[str] | None) -> Set[str] | None:
    if not values:
        return None
    tokens: Set[str] = set()
    for value in values:
        for token in value.split(","):
            token = token.strip()
            if token:
                tokens.add(token)
    return tokens or None


def plan_commands(
    hosts: Iterable[Host],
    *,
    include_services: Set[str] | None = None,
    exclude_services: Set[str] | None = None,
    credentials: ADCredentials | None = None,
) -> List[PlannedCommand]:
    profiles = build_service_profiles()
    commands: List[PlannedCommand] = []
    creds = credentials or ADCredentials()
    credential_values = {
        "ad_user": creds.username or "",
        "ad_password": creds.password or "",
        "ad_domain": creds.domain or "",
    }
    credential_presence = {
        "ad_user": creds.username is not None,
        "ad_password": creds.password is not None,
        "ad_domain": creds.domain is not None,
    }

    def service_allowed(name: str) -> bool:
        if include_services and name not in include_services:
            return False
        if exclude_services and name in exclude_services:
            return False
        return True

    for host in hosts:
        host_ports = ",".join(str(s.port) for s in host.services)
        if service_allowed("multipuerto"):
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
                    if not service_allowed(profile.name):
                        continue
                    for description, template in profile.commands:
                        format_context = {
                            "host": service.host_ip,
                            "port": str(service.port),
                            **credential_values,
                        }
                        commands.append(
                            PlannedCommand(
                                host_ip=service.host_ip,
                                service=profile.name,
                                port=service.port,
                                description=description,
                                command=_format_command(template, format_context, credential_presence),
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
    commands_by_host: dict[str, List[PlannedCommand]] = {}
    for command in commands:
        commands_by_host.setdefault(command.host_ip, []).append(command)

    semaphore = threading.Semaphore(max_workers)

    def host_worker(host_ip: str, host_commands: List[PlannedCommand]) -> None:
        with semaphore:
            for cmd in host_commands:
                run_command(cmd, dry_run=dry_run)

    threads: List[threading.Thread] = []
    for host_ip, host_commands in commands_by_host.items():
        thread = threading.Thread(target=host_worker, args=(host_ip, host_commands), daemon=True)
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
    parser.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Número máximo de hosts procesados en paralelo",
    )
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar los comandos que se ejecutarían")
    parser.add_argument(
        "--only-hosts",
        nargs="*",
        help="Filtra los hosts a incluir (IPs u hostnames separados por espacios o comas)",
    )
    parser.add_argument(
        "--skip-hosts",
        nargs="*",
        help="Hosts a omitir (IPs u hostnames separados por espacios o comas)",
    )
    parser.add_argument(
        "--only-services",
        nargs="*",
        help="Ejecuta únicamente los perfiles indicados (por ejemplo: http smb multipuerto)",
    )
    parser.add_argument(
        "--skip-services",
        nargs="*",
        help="Perfiles a omitir por nombre (por ejemplo: http smb multipuerto)",
    )
    parser.add_argument("--ad-user", help="Usuario de Active Directory para reutilizar en los comandos soportados")
    parser.add_argument("--ad-password", help="Contraseña del usuario de Active Directory")
    parser.add_argument("--ad-domain", help="Dominio de Active Directory asociado a las credenciales")
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

    include_hosts = _normalize_filter_values(args.only_hosts)
    exclude_hosts = _normalize_filter_values(args.skip_hosts)

    if include_hosts:
        hosts = [host for host in hosts if host.ip in include_hosts or (host.hostname and host.hostname in include_hosts)]
    if exclude_hosts:
        hosts = [host for host in hosts if host.ip not in exclude_hosts and (not host.hostname or host.hostname not in exclude_hosts)]

    if not hosts:
        raise SystemExit("Los filtros aplicados eliminaron todos los hosts del XML")

    include_services = _normalize_filter_values(args.only_services)
    exclude_services = _normalize_filter_values(args.skip_services)

    credentials = ADCredentials(username=args.ad_user, password=args.ad_password, domain=args.ad_domain)
    commands = plan_commands(
        hosts,
        include_services=include_services,
        exclude_services=exclude_services,
        credentials=credentials,
    )
    output_dir = Path(args.output)
    prepare_log_paths(commands, output_dir)
    execute_commands(commands, args.dry_run, args.max_workers)
    write_summary_files(hosts, commands, output_dir)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
