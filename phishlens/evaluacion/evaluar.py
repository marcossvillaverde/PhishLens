"""
Evaluación de PhishLens con correos reales etiquetados (hito 8).

Para cada correo del manifiesto (preparado con preparar.py) se calcula:
  - reglas:         veredicto del motor determinista.
  - sistema:        veredicto final de PhishLens (reglas + IA combinadas).
  - IA con datos:   lo que opina el modelo cuando ve los datos técnicos y el
                    veredicto de las reglas (como en el uso normal).
  - IA sola:        lo que opina el modelo viendo SOLO el contenido del correo
                    (ablación: mide cuánto detecta por sí mismo, sin anclaje).

Se trabaja sin red (autenticación leída de las cabeceras, sin reputación):
los correos son antiguos y sus enlaces ya no existen, así que consultar hoy
el DNS o VirusTotal no reflejaría la situación del momento del envío.

Los resultados de cada correo se guardan según se calculan (se puede
interrumpir con Ctrl+C y reanudar). El resumen, sin contenido de los correos,
se guarda en docs/resultados/ como evidencia.

Por defecto usa el conjunto de desarrollo; con --conjunto prueba, el de prueba,
que es el que da las cifras finales (no se usa para ajustar nada).

Uso:
    python -m phishlens.evaluacion.evaluar --sin-ia        (solo reglas: segundos)
    python -m phishlens.evaluacion.evaluar --limite 10     (prueba rápida con IA)
    python -m phishlens.evaluacion.evaluar                 (completo: puede tardar ~45 min)
"""

import argparse
import csv
import json
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from phishlens.checks.autenticacion import comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.checks.modelos import Severidad
from phishlens.combinacion import combinar
from phishlens.config import RAIZ_PROYECTO, cargar_config
from phishlens.evaluacion.preparar import CARPETAS
from phishlens.llm.analizador import analizar_con_ia
from phishlens.llm.proveedores import ErrorProveedor, crear_proveedor
from phishlens.llm.saneamiento import sanear
from phishlens.parser import parsear_bytes
from phishlens.scoring import puntuar

consola = Console()


@dataclass
class ResultadoCorreo:
    fichero: str
    etiqueta: str                      # "phishing" o "legitimo" (la verdad)
    fuente: str
    sha256: str
    puntuacion: int = 0
    veredicto_reglas: str = ""
    hallazgos: list[str] = field(default_factory=list)   # códigos que suman riesgo
    veredicto_sistema: str | None = None
    prob_ia_con_datos: float | None = None
    prob_ia_sola: float | None = None
    error_ia: str = ""
    segundos_ia: float = 0.0


# ---------------------------------------------------------------- análisis

def evaluar_correo(ruta: Path, fila: dict, proveedor=None) -> ResultadoCorreo:
    correo = parsear_bytes(ruta.read_bytes())
    auth, hallazgos = comprobar_autenticacion(correo, en_linea=False)
    hallazgos += comprobar_heuristicas(correo)
    saneado = sanear(correo)
    hallazgos += saneado.hallazgos
    puntuacion = puntuar(hallazgos)

    r = ResultadoCorreo(
        fichero=fila["fichero"], etiqueta=fila["etiqueta"], fuente=fila["fuente"], sha256=fila["sha256"],
        puntuacion=puntuacion.puntuacion, veredicto_reglas=puntuacion.veredicto.value,
        hallazgos=sorted({h.codigo for h in hallazgos if h.severidad != Severidad.INFO}),
    )
    if proveedor is None:
        return r

    inicio = time.monotonic()
    ia = analizar_con_ia(correo, saneado, auth, hallazgos, puntuacion, proveedor)
    r.veredicto_sistema = combinar(puntuacion, ia).veredicto.value
    if ia.analisis:
        r.prob_ia_con_datos = ia.analisis.probabilidad_phishing
    ia_sola = analizar_con_ia(correo, saneado, auth, hallazgos, puntuacion, proveedor, solo_contenido=True)
    if ia_sola.analisis:
        r.prob_ia_sola = ia_sola.analisis.probabilidad_phishing
    r.error_ia = "; ".join(e for e in (ia.error, ia_sola.error) if e)
    r.segundos_ia = round(time.monotonic() - inicio, 1)
    return r


def cargar_manifiesto(carpeta: Path) -> list[dict]:
    ruta = carpeta / "manifiesto.csv"
    if not ruta.is_file():
        raise FileNotFoundError(f"no existe {ruta}: ejecuta antes python -m phishlens.evaluacion.preparar")
    with ruta.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cargar_cache(ruta: Path) -> dict[str, dict]:
    if not ruta.is_file():
        return {}
    cache = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if linea.strip():
            datos = json.loads(linea)
            cache[datos["sha256"]] = datos
    return cache


# ---------------------------------------------------------------- métricas

def metricas(pares: list[tuple[bool, bool]]) -> dict:
    """pares = [(es_phishing_de_verdad, detectado_como_phishing), ...]"""
    vp = sum(1 for real, pred in pares if real and pred)
    fp = sum(1 for real, pred in pares if not real and pred)
    vn = sum(1 for real, pred in pares if not real and not pred)
    fn = sum(1 for real, pred in pares if real and not pred)
    total = len(pares)

    def div(a, b):
        return a / b if b else 0.0

    precision, deteccion = div(vp, vp + fp), div(vp, vp + fn)
    return {
        "n": total, "vp": vp, "fp": fp, "vn": vn, "fn": fn,
        "exactitud": div(vp + vn, total),
        "precision": precision,
        "deteccion": deteccion,                       # recall / tasa de verdaderos positivos
        "falsos_positivos": div(fp, fp + vn),         # tasa de falsos positivos
        "f1": div(2 * precision * deteccion, precision + deteccion),
    }


def configuraciones(resultados: list[ResultadoCorreo]) -> dict[str, dict]:
    """Calcula las métricas de cada configuración (solo con los correos que tienen dato)."""
    def pares(prediccion):
        return [(r.etiqueta == "phishing", p) for r in resultados if (p := prediccion(r)) is not None]

    salida = {
        "Reglas (sospechoso o phishing)": metricas(pares(lambda r: r.veredicto_reglas != "limpio")),
        "Reglas (solo phishing)": metricas(pares(lambda r: r.veredicto_reglas == "phishing")),
    }
    if any(r.veredicto_sistema for r in resultados):
        salida["Sistema completo: reglas + IA"] = metricas(
            pares(lambda r: None if r.veredicto_sistema is None else r.veredicto_sistema != "limpio"))
        salida["IA con datos técnicos (≥ 50 %)"] = metricas(
            pares(lambda r: None if r.prob_ia_con_datos is None else r.prob_ia_con_datos >= 0.5))
        salida["IA sola, solo contenido (≥ 50 %)"] = metricas(
            pares(lambda r: None if r.prob_ia_sola is None else r.prob_ia_sola >= 0.5))
    return salida


# ---------------------------------------------------------------- salida

def mostrar_tabla(por_config: dict[str, dict]) -> None:
    tabla = Table(title="Resultados de la evaluación")
    tabla.add_column("Configuración")
    for col in ("n", "Exactitud", "Detección", "Falsos positivos", "Precisión", "F1", "VP/FP/VN/FN"):
        tabla.add_column(col, justify="right")
    for nombre, m in por_config.items():
        tabla.add_row(nombre, str(m["n"]), f"{m['exactitud']:.1%}", f"{m['deteccion']:.1%}",
                      f"{m['falsos_positivos']:.1%}", f"{m['precision']:.1%}", f"{m['f1']:.2f}",
                      f"{m['vp']}/{m['fp']}/{m['vn']}/{m['fn']}")
    consola.print(tabla)


def analisis_de_errores(resultados: list[ResultadoCorreo]) -> dict:
    """Qué hallazgos provocan los falsos positivos y qué phishing se escapa (según las reglas)."""
    falsos_pos = [r for r in resultados if r.etiqueta == "legitimo" and r.veredicto_reglas != "limpio"]
    falsos_neg = [r for r in resultados if r.etiqueta == "phishing" and r.veredicto_reglas == "limpio"]
    return {
        "causas_fp": Counter(c for r in falsos_pos for c in r.hallazgos).most_common(8),
        "falsos_negativos": [(r.fichero, r.puntuacion, r.hallazgos) for r in falsos_neg],
        "hallazgos_en_phishing": Counter(c for r in resultados if r.etiqueta == "phishing"
                                         for c in r.hallazgos).most_common(10),
    }


def guardar_resumen(resultados: list[ResultadoCorreo], por_config: dict, modelo: str,
                    conjunto: str = "desarrollo") -> Path:
    """Resumen para la memoria: métricas y análisis de errores, sin contenido de los correos."""
    carpeta = RAIZ_PROYECTO / "docs" / "resultados"
    carpeta.mkdir(parents=True, exist_ok=True)
    nombre_modelo = re.sub(r"[^a-zA-Z0-9.]+", "-", modelo).strip("-") or "sin-ia"
    ruta = carpeta / f"evaluacion_{conjunto}_{nombre_modelo}_{datetime.now():%Y-%m-%d_%H%M}.md"
    errores = analisis_de_errores(resultados)
    n_phish = sum(1 for r in resultados if r.etiqueta == "phishing")
    fuentes = Counter(r.fuente for r in resultados)

    lineas = [
        "# Evaluación de PhishLens con correos reales", "",
        f"- Fecha: {datetime.now():%Y-%m-%d %H:%M}",
        f"- Conjunto: {conjunto}",
        f"- Modelo de IA: {modelo or 'no usado'}",
        f"- Correos: {len(resultados)} ({n_phish} de phishing, {len(resultados) - n_phish} legítimos)",
        f"- Fuentes: {', '.join(f'{k} ({v})' for k, v in fuentes.items())}",
        "- Modo: sin red (autenticación según las cabeceras del propio correo, sin reputación)", "",
        "## Métricas", "",
        "| Configuración | n | Exactitud | Detección | Falsos positivos | Precisión | F1 | VP/FP/VN/FN |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for nombre, m in por_config.items():
        lineas.append(f"| {nombre} | {m['n']} | {m['exactitud']:.1%} | {m['deteccion']:.1%} | "
                      f"{m['falsos_positivos']:.1%} | {m['precision']:.1%} | {m['f1']:.2f} | "
                      f"{m['vp']}/{m['fp']}/{m['vn']}/{m['fn']} |")
    lineas += ["", "Detección = phishing detectado / total de phishing. "
               "Falsos positivos = legítimos marcados / total de legítimos.", "",
               "## Hallazgos que provocan falsos positivos (reglas)", ""]
    lineas += [f"- {codigo}: {n}" for codigo, n in errores["causas_fp"]] or ["- ninguno"]
    lineas += ["", "## Hallazgos más frecuentes en el phishing", ""]
    lineas += [f"- {codigo}: {n}" for codigo, n in errores["hallazgos_en_phishing"]]
    lineas += ["", "## Phishing no detectado por las reglas", ""]
    lineas += [f"- {f} (puntuación {p}; {', '.join(h) or 'sin hallazgos'})"
               for f, p, h in errores["falsos_negativos"]] or ["- ninguno"]
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return ruta


# ---------------------------------------------------------------- principal

def ejecutar(carpeta: Path, proveedor=None, limite: int | None = None, reiniciar: bool = False) -> list[ResultadoCorreo]:
    filas = cargar_manifiesto(carpeta)
    if limite:
        filas = ([f for f in filas if f["etiqueta"] == "phishing"][:limite]
                 + [f for f in filas if f["etiqueta"] == "legitimo"][:limite])

    nombre = re.sub(r"[^a-zA-Z0-9.]+", "-", proveedor.nombre).strip("-") if proveedor else "reglas"
    ruta_cache = carpeta / f"resultados_{nombre}.jsonl"
    if reiniciar and ruta_cache.exists():
        ruta_cache.unlink()
    cache = cargar_cache(ruta_cache)

    resultados = []
    with ruta_cache.open("a", encoding="utf-8") as salida:
        for i, fila in enumerate(filas, 1):
            guardado = cache.get(fila["sha256"])
            # Se reutiliza lo guardado, salvo que la IA hubiera fallado: en ese caso se reintenta
            if guardado and not (proveedor and guardado.get("error_ia")):
                resultados.append(ResultadoCorreo(**guardado))
                continue
            with consola.status(f"{i}/{len(filas)}: {escape(fila['fichero'])}"):
                try:
                    r = evaluar_correo(carpeta / fila["fichero"], fila, proveedor)
                except Exception as exc:   # un correo roto no debe detener la evaluación
                    consola.print(f"[yellow]Error con {escape(fila['fichero'])}: {escape(str(exc))}[/yellow]")
                    continue
            salida.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
            salida.flush()
            resultados.append(r)
            if proveedor:
                consola.print(f"[dim]{i}/{len(filas)} {escape(r.fichero)}: reglas={r.veredicto_reglas}, "
                              f"sistema={r.veredicto_sistema}, IA={r.prob_ia_con_datos}, IA sola={r.prob_ia_sola} "
                              f"({r.segundos_ia} s)[/dim]")
    return resultados


def main() -> int:
    argumentos = argparse.ArgumentParser(description="Evalúa PhishLens con el corpus etiquetado")
    argumentos.add_argument("--conjunto", choices=["desarrollo", "prueba"], default="desarrollo")
    argumentos.add_argument("--sin-ia", action="store_true", help="evaluar solo las reglas (rápido)")
    argumentos.add_argument("--limite", type=int, help="usar solo N correos de cada tipo (prueba rápida)")
    argumentos.add_argument("--reiniciar", action="store_true", help="ignorar los resultados guardados")
    args = argumentos.parse_args()

    proveedor = None
    if not args.sin_ia:
        try:
            proveedor = crear_proveedor(cargar_config())
        except ErrorProveedor as exc:
            consola.print(f"[red]Error:[/red] {escape(str(exc))}")
            return 1

    try:
        resultados = ejecutar(CARPETAS[args.conjunto], proveedor, args.limite, args.reiniciar)
    except FileNotFoundError as exc:
        consola.print(f"[red]Error:[/red] {escape(str(exc))}")
        return 1

    por_config = configuraciones(resultados)
    mostrar_tabla(por_config)
    errores = analisis_de_errores(resultados)
    consola.print("\n[bold]Hallazgos que más falsos positivos provocan:[/bold] "
                  + (", ".join(f"{c} ({n})" for c, n in errores["causas_fp"]) or "ninguno"))
    consola.print(f"[bold]Phishing que las reglas no detectan:[/bold] {len(errores['falsos_negativos'])}")
    con_error = sum(1 for r in resultados if r.error_ia)
    if con_error:
        consola.print(f"[yellow]{con_error} correos con algún error de la IA (se usó solo el veredicto de las reglas)[/yellow]")

    ruta = guardar_resumen(resultados, por_config, proveedor.nombre if proveedor else "", args.conjunto)
    consola.print(f"\nResumen guardado en [cyan]{ruta.relative_to(RAIZ_PROYECTO)}[/cyan]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
