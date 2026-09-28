"""
Punto de entrada de PhishLens por línea de comandos.

Uso:
    python -m phishlens.main correo.eml                   análisis completo
    python -m phishlens.main correo.eml --sin-ia          sin el análisis del modelo de lenguaje
    python -m phishlens.main correo.eml --sin-reputacion  sin consultar VirusTotal, AbuseIPDB ni urlscan
    python -m phishlens.main correo.eml --sin-red         sin conexiones a internet (ni DNS, ni reputación,
                                                          ni API externa; Ollama local sí se usa)
    python -m phishlens.main correo.eml --informe         además, guarda el informe HTML y JSON en reports/
    python -m phishlens.main correo.eml --informe DIR     ... o en la carpeta indicada

Seguridad: todo el texto que procede del correo o de la IA se muestra con
escape() para que no pueda inyectar marcas de formato en la terminal
(por ejemplo, un asunto con "[link=...]" que cree enlaces falsos).
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from phishlens.analisis import OpcionesAnalisis, ResultadoAnalisis, analizar
from phishlens.checks.autenticacion import ResultadoAutenticacion
from phishlens.checks.modelos import Hallazgo, Severidad
from phishlens.combinacion import VeredictoFinal
from phishlens.config import RAIZ_PROYECTO, cargar_config
from phishlens.enrichment.base import ResultadoReputacion
from phishlens.llm.analizador import ResultadoIA
from phishlens.parser import CorreoParseado
from phishlens.report import guardar_informes
from phishlens.scoring import ResultadoPuntuacion, Veredicto

consola = Console()

# Colores para cada severidad en la terminal
COLORES = {
    Severidad.INFO: "white",
    Severidad.BAJA: "green",
    Severidad.MEDIA: "yellow",
    Severidad.ALTA: "red",
    Severidad.CRITICA: "bold red",
}
COLORES_VEREDICTO = {Veredicto.LIMPIO: "green", Veredicto.SOSPECHOSO: "yellow", Veredicto.PHISHING: "bold red"}


def mostrar_parseo(correo: CorreoParseado) -> None:
    """Muestra por pantalla lo que el parser ha extraído del correo."""
    # --- Cabeceras ---
    tabla = Table(title="Cabeceras", show_header=False)
    tabla.add_column("Campo", style="bold cyan")
    tabla.add_column("Valor")
    tabla.add_row("From", escape(f"{correo.remitente_nombre} <{correo.remitente}>"))
    tabla.add_row("Reply-To", escape(correo.reply_to or "-"))
    tabla.add_row("Return-Path", escape(correo.return_path or "-"))
    tabla.add_row("Para", escape(", ".join(correo.destinatarios) or "-"))
    tabla.add_row("Asunto", escape(correo.asunto or "-"))
    tabla.add_row("Fecha", escape(correo.fecha or "-"))
    tabla.add_row("IP de origen", correo.ip_origen or "no encontrada")
    tabla.add_row("Saltos (Received)", str(len(correo.received)))
    consola.print(tabla)

    # --- URLs ---
    tabla = Table(title=f"URLs ({len(correo.urls)})")
    tabla.add_column("Destino real", style="red")
    tabla.add_column("Texto visible")
    tabla.add_column("Origen")
    for url in correo.urls:
        tabla.add_row(escape(url.url), escape(url.texto_visible or "-"), url.origen)
    consola.print(tabla)

    # --- Adjuntos ---
    tabla = Table(title=f"Adjuntos ({len(correo.adjuntos)})")
    tabla.add_column("Nombre")
    tabla.add_column("Tipo")
    tabla.add_column("Tamaño")
    tabla.add_column("SHA-256")
    for adjunto in correo.adjuntos:
        tabla.add_row(escape(adjunto.nombre), escape(adjunto.tipo_mime), f"{adjunto.tamano} B", adjunto.sha256)
    consola.print(tabla)


def mostrar_autenticacion(resultado: ResultadoAutenticacion) -> None:
    """Muestra el resumen de SPF, DKIM y DMARC."""
    fuente = "verificación DNS propia" if resultado.fuente == "en_linea" else "cabecera Authentication-Results"
    tabla = Table(title=f"Autenticación ({fuente})", show_header=False)
    tabla.add_column("Mecanismo", style="bold cyan")
    tabla.add_column("Resultado")
    tabla.add_row("SPF", escape(resultado.spf))
    tabla.add_row("DKIM", escape(resultado.dkim))
    tabla.add_row("DMARC", escape(resultado.dmarc))
    if resultado.politica_dmarc:
        tabla.add_row("Política DMARC", escape(resultado.politica_dmarc))
    consola.print(tabla)


def mostrar_reputacion(resultados: list[ResultadoReputacion]) -> None:
    """Muestra lo que han respondido los servicios de reputación."""
    tabla = Table(title=f"Reputación ({len(resultados)} consultas)")
    tabla.add_column("Servicio", style="bold cyan")
    tabla.add_column("Tipo")
    tabla.add_column("Indicador", overflow="fold")
    tabla.add_column("Resultado")
    for r in resultados:
        if r.error:
            texto = f"[yellow]error: {escape(r.error)}[/yellow]"
        elif not r.encontrado:
            texto = "[dim]sin datos[/dim]"
        elif r.servicio == "virustotal":
            texto = f"{r.datos['maliciosos']} maliciosos / {r.datos['sospechosos']} sospechosos"
        elif r.servicio == "abuseipdb":
            texto = f"abuso {r.datos['puntuacion_abuso']}/100 ({r.datos['total_reportes']} reportes)"
        else:
            texto = f"{r.datos['escaneos_previos']} escaneos previos"
        if r.desde_cache:
            texto += " [dim](caché)[/dim]"
        indicador = r.indicador if len(r.indicador) <= 70 else r.indicador[:67] + "..."
        tabla.add_row(r.servicio, r.tipo, escape(indicador), texto)
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
        tabla.add_row(f"[{color}]{h.severidad.value.upper()}[/{color}]", h.codigo,
                      escape(h.descripcion), escape(h.evidencia or "-"))
    consola.print(tabla)


def mostrar_puntuacion(resultado: ResultadoPuntuacion) -> None:
    """Muestra la puntuación y el veredicto de las reglas deterministas."""
    color = COLORES_VEREDICTO[resultado.veredicto]
    desglose = "  ".join(f"{codigo} +{puntos}" for codigo, puntos in resultado.desglose.items() if puntos)
    consola.print(Panel(
        f"[{color}]Veredicto: {resultado.veredicto.value.upper()}[/{color}]\n"
        f"Puntuación de riesgo: [bold]{resultado.puntuacion}/100[/bold]\n\n"
        f"[dim]{desglose or 'Sin hallazgos que sumen riesgo'}[/dim]",
        title="Resultado (reglas deterministas)",
        border_style=color,
    ))


def mostrar_ia(resultado: ResultadoIA) -> None:
    """Muestra el análisis del modelo de lenguaje."""
    titulo = f"Análisis de IA — {escape(resultado.proveedor)} — {resultado.segundos} s"
    if resultado.analisis is None:
        consola.print(Panel(f"[yellow]No disponible: {escape(resultado.error)}[/yellow]",
                            title=titulo, border_style="yellow"))
        return

    a = resultado.analisis
    lineas = [
        f"[bold]Probabilidad de phishing:[/bold] {a.probabilidad_phishing:.0%} "
        f"({'phishing probable' if a.es_phishing_probable else 'probablemente legítimo'})",
        f"[bold]Tipo de fraude:[/bold] {escape(a.tipo_fraude)}",
        f"[bold]Tácticas:[/bold] {escape(', '.join(a.tacticas) or '-')}",
        f"[bold]MITRE ATT&CK:[/bold] {escape(', '.join(a.tecnicas_mitre) or '-')}",
        "",
        f"[bold]Explicación:[/bold] {escape(a.explicacion)}",
        f"[bold]Recomendación:[/bold] {escape(a.recomendacion or '-')}",
    ]
    if resultado.avisos:
        lineas += ["", f"[dim]Avisos de validación: {escape('; '.join(resultado.avisos))}[/dim]"]
    consola.print(Panel("\n".join(lineas), title=titulo, border_style="cyan"))


def mostrar_veredicto_final(final: VeredictoFinal) -> None:
    color = COLORES_VEREDICTO[final.veredicto]
    revision = "[bold yellow]Sí[/bold yellow]" if final.revision_manual else "No"
    consola.print(Panel(
        f"[{color}]VEREDICTO FINAL: {final.veredicto.value.upper()}[/{color}]\n"
        f"Puntuación de las reglas: {final.puntuacion_reglas}/100 "
        f"(veredicto de las reglas: {final.veredicto_reglas.value})\n"
        f"Revisión manual recomendada: {revision}\n\n"
        f"{escape(final.motivo)}",
        title="Resultado final",
        border_style=color,
    ))


def mostrar_resultado(r: ResultadoAnalisis) -> None:
    """Muestra en la terminal todas las secciones del análisis."""
    mostrar_parseo(r.correo)
    mostrar_autenticacion(r.autenticacion)
    if r.opciones.reputacion and r.opciones.en_linea:
        mostrar_reputacion(r.reputacion)
    mostrar_hallazgos(r.hallazgos)
    mostrar_puntuacion(r.puntuacion)
    if r.ia is not None:
        mostrar_ia(r.ia)
    mostrar_veredicto_final(r.final)


def main() -> int:
    argumentos = argparse.ArgumentParser(
        prog="phishlens",
        description="Analizador de correos de phishing con IA",
    )
    argumentos.add_argument("eml", type=Path, help="ruta al fichero .eml a analizar")
    argumentos.add_argument("--sin-ia", action="store_true", help="no usar el modelo de lenguaje")
    argumentos.add_argument(
        "--sin-reputacion", action="store_true",
        help="no consultar VirusTotal, AbuseIPDB ni urlscan.io",
    )
    argumentos.add_argument(
        "--sin-red", action="store_true",
        help="sin conexiones a internet: ni DNS, ni reputación, ni API externa (Ollama local sí)",
    )
    argumentos.add_argument(
        "--informe", nargs="?", const=RAIZ_PROYECTO / "reports", type=Path, metavar="CARPETA",
        help="guardar el informe en HTML y JSON (por defecto en reports/)",
    )
    args = argumentos.parse_args()

    if not args.eml.is_file():
        consola.print(f"[red]Error:[/red] no existe el fichero {escape(str(args.eml))}")
        return 1

    opciones = OpcionesAnalisis(en_linea=not args.sin_red, reputacion=not args.sin_reputacion, ia=not args.sin_ia)
    resultado = analizar(args.eml, cargar_config(), opciones,
                         avisar=lambda mensaje: consola.print(f"[dim]{escape(mensaje)}[/dim]"))
    mostrar_resultado(resultado)

    if args.informe:
        html, json_ = guardar_informes(resultado, args.informe)
        consola.print(f"\nInforme HTML: [cyan]{escape(str(html))}[/cyan]")
        consola.print(f"Informe JSON: [cyan]{escape(str(json_))}[/cyan]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
