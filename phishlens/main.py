"""
Punto de entrada de PhishLens por línea de comandos.

Uso:
    python -m phishlens.main ruta/al/correo.eml
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from phishlens.parser import parsear_eml

consola = Console()


def mostrar_parseo(ruta: Path) -> None:
    """Muestra por pantalla lo que el parser ha extraído del correo."""
    correo = parsear_eml(ruta)

    # --- Cabeceras ---
    tabla = Table(title="Cabeceras", show_header=False)
    tabla.add_column("Campo", style="bold cyan")
    tabla.add_column("Valor")
    tabla.add_row("From", f"{correo.remitente_nombre} <{correo.remitente}>")
    tabla.add_row("Reply-To", correo.reply_to or "-")
    tabla.add_row("Return-Path", correo.return_path or "-")
    tabla.add_row("Para", ", ".join(correo.destinatarios) or "-")
    tabla.add_row("Asunto", correo.asunto or "-")
    tabla.add_row("Fecha", correo.fecha or "-")
    tabla.add_row("IP de origen", correo.ip_origen or "no encontrada")
    tabla.add_row("Saltos (Received)", str(len(correo.received)))
    consola.print(tabla)

    # --- URLs ---
    tabla = Table(title=f"URLs ({len(correo.urls)})")
    tabla.add_column("Destino real", style="red")
    tabla.add_column("Texto visible")
    tabla.add_column("Origen")
    for url in correo.urls:
        tabla.add_row(url.url, url.texto_visible or "-", url.origen)
    consola.print(tabla)

    # --- Adjuntos ---
    tabla = Table(title=f"Adjuntos ({len(correo.adjuntos)})")
    tabla.add_column("Nombre")
    tabla.add_column("Tipo")
    tabla.add_column("Tamaño")
    tabla.add_column("SHA-256")
    for adjunto in correo.adjuntos:
        tabla.add_row(adjunto.nombre, adjunto.tipo_mime, f"{adjunto.tamano} B", adjunto.sha256)
    consola.print(tabla)


def main() -> int:
    argumentos = argparse.ArgumentParser(
        prog="phishlens",
        description="Analizador de correos de phishing con IA",
    )
    argumentos.add_argument("eml", type=Path, help="ruta al fichero .eml a analizar")
    args = argumentos.parse_args()

    if not args.eml.is_file():
        consola.print(f"[red]Error:[/red] no existe el fichero {args.eml}")
        return 1

    mostrar_parseo(args.eml)
    return 0


if __name__ == "__main__":
    sys.exit(main())
