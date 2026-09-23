"""
Punto de entrada de PhishLens por línea de comandos.

Uso:
    python -m phishlens.main ruta/al/correo.eml            (con verificación DNS en línea)
    python -m phishlens.main ruta/al/correo.eml --sin-red  (solo datos del propio correo)
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phishlens.checks.autenticacion import ResultadoAutenticacion, comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.checks.modelos import Hallazgo, Severidad
from phishlens.parser import CorreoParseado, parsear_eml
from phishlens.scoring import ResultadoPuntuacion, Veredicto, puntuar

consola = Console()

# Colores para cada severidad en la terminal
COLORES = {
    Severidad.INFO: "white",
    Severidad.BAJA: "green",
    Severidad.MEDIA: "yellow",
    Severidad.ALTA: "red",
    Severidad.CRITICA: "bold red",
}


def mostrar_parseo(correo: CorreoParseado) -> None:
    """Muestra por pantalla lo que el parser ha extraído del correo."""
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


def mostrar_autenticacion(resultado: ResultadoAutenticacion) -> None:
    """Muestra el resumen de SPF, DKIM y DMARC."""
    fuente = "verificación DNS propia" if resultado.fuente == "en_linea" else "cabecera Authentication-Results"
    tabla = Table(title=f"Autenticación ({fuente})", show_header=False)
    tabla.add_column("Mecanismo", style="bold cyan")
    tabla.add_column("Resultado")
    tabla.add_row("SPF", resultado.spf)
    tabla.add_row("DKIM", resultado.dkim)
    tabla.add_row("DMARC", resultado.dmarc)
    if resultado.politica_dmarc:
        tabla.add_row("Política DMARC", resultado.politica_dmarc)
    consola.print(tabla)


def mostrar_hallazgos(hallazgos: list[Hallazgo]) -> None:
    """Muestra los hallazgos ordenados de más a menos grave."""
    orden = list(Severidad)
    hallazgos = sorted(hallazgos, key=lambda h: orden.index(h.severidad), reverse=True)

    tabla = Table(title=f"Hallazgos ({len(hallazgos)})")
    tabla.add_column("Severidad")
    tabla.add_column("Código", style="bold")
    tabla.add_column("Descripción")
    tabla.add_column("Evidencia", style="dim")
    for h in hallazgos:
        color = COLORES[h.severidad]
        tabla.add_row(f"[{color}]{h.severidad.value.upper()}[/{color}]", h.codigo, h.descripcion, h.evidencia or "-")
    consola.print(tabla)


def mostrar_puntuacion(resultado: ResultadoPuntuacion) -> None:
    """Muestra la puntuación final y el veredicto de las reglas deterministas."""
    colores = {Veredicto.LIMPIO: "green", Veredicto.SOSPECHOSO: "yellow", Veredicto.PHISHING: "bold red"}
    color = colores[resultado.veredicto]
    desglose = "  ".join(f"{codigo} +{puntos}" for codigo, puntos in resultado.desglose.items() if puntos)
    consola.print(Panel(
        f"[{color}]Veredicto: {resultado.veredicto.value.upper()}[/{color}]\n"
        f"Puntuación de riesgo: [bold]{resultado.puntuacion}/100[/bold]\n\n"
        f"[dim]{desglose or 'Sin hallazgos que sumen riesgo'}[/dim]",
        title="Resultado (reglas deterministas)",
        border_style=color,
    ))


def main() -> int:
    argumentos = argparse.ArgumentParser(
        prog="phishlens",
        description="Analizador de correos de phishing con IA",
    )
    argumentos.add_argument("eml", type=Path, help="ruta al fichero .eml a analizar")
    argumentos.add_argument(
        "--sin-red", action="store_true",
        help="no hacer consultas DNS; usar solo la cabecera Authentication-Results",
    )
    args = argumentos.parse_args()

    if not args.eml.is_file():
        consola.print(f"[red]Error:[/red] no existe el fichero {args.eml}")
        return 1

    correo = parsear_eml(args.eml)
    mostrar_parseo(correo)

    resultado_auth, hallazgos_auth = comprobar_autenticacion(correo, en_linea=not args.sin_red)
    mostrar_autenticacion(resultado_auth)

    hallazgos = hallazgos_auth + comprobar_heuristicas(correo)
    mostrar_hallazgos(hallazgos)

    mostrar_puntuacion(puntuar(hallazgos))
    return 0


if __name__ == "__main__":
    sys.exit(main())
