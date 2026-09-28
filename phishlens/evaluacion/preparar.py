"""
Preparación del corpus de evaluación (hito 8).

Descarga una muestra reproducible de correos reales y etiquetados:
  - Phishing: Phishing Pot (github.com/rf-peixoto/phishing_pot), correos de
    phishing reales capturados con honeypots. Licencia CC BY-NC 4.0 (uso
    académico permitido, citando la fuente).
  - Legítimos: parte "easy_ham" del corpus público de SpamAssassin
    (spamassassin.apache.org/old/publiccorpus/), correo legítimo de listas y
    particulares de 2002, de uso libre para investigación.
  - Opcional: correos legítimos propios en samples/evaluacion/legitimo_propio/.

Todo se guarda en samples/evaluacion/ (ignorada por Git). Los correos de
phishing son REALES: solo se guardan como ficheros, nunca se abren con un
cliente de correo.

Uso:
    python -m phishlens.evaluacion.preparar                 (100 + 100 por defecto)
    python -m phishlens.evaluacion.preparar --phishing 50 --legitimos 50
"""

import argparse
import csv
import hashlib
import random
import sys
import tarfile
from pathlib import Path

import requests
from rich.console import Console

from phishlens.config import RAIZ_PROYECTO

consola = Console()

SEMILLA = 42   # misma semilla = misma muestra: la evaluación es reproducible
CARPETA = RAIZ_PROYECTO / "samples" / "evaluacion"
URL_PHISHING = "https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-{n}.eml"
MAX_INDICE_PHISHING = 5000
URL_HAM = "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
TIMEOUT = 20


def _sha256(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def descargar_phishing(cantidad: int, destino: Path, sesion=None) -> list[Path]:
    """Descarga `cantidad` correos de Phishing Pot elegidos al azar (con semilla fija)."""
    sesion = sesion or requests.Session()
    destino.mkdir(parents=True, exist_ok=True)
    candidatos = random.Random(SEMILLA).sample(range(1, MAX_INDICE_PHISHING + 1), MAX_INDICE_PHISHING)
    guardados: list[Path] = []
    vistos: set[str] = set()

    for n in candidatos:
        if len(guardados) >= cantidad:
            break
        ruta = destino / f"phishing_pot-sample-{n}.eml"
        if ruta.exists():                          # ya descargado en una ejecución anterior
            vistos.add(_sha256(ruta.read_bytes()))
            guardados.append(ruta)
            continue
        try:
            respuesta = sesion.get(URL_PHISHING.format(n=n), timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if respuesta.status_code != 200 or not respuesta.content:
            continue
        huella = _sha256(respuesta.content)
        if huella in vistos:                        # descarta duplicados exactos
            continue
        vistos.add(huella)
        ruta.write_bytes(respuesta.content)
        guardados.append(ruta)
        consola.print(f"[dim]phishing {len(guardados)}/{cantidad}: {ruta.name}[/dim]")
    return guardados


def extraer_legitimos(archivo_tar: Path, cantidad: int, destino: Path) -> list[Path]:
    """
    Extrae `cantidad` correos del tar de SpamAssassin, elegidos al azar (con semilla fija).

    Se usa el filtro "data" de tarfile: impide que un tar malicioso escriba fuera
    de la carpeta de destino (rutas con ../ o absolutas), cree enlaces o ficheros
    especiales. Además, solo se leen ficheros regulares, sin extraer nada a disco
    directamente desde el tar.
    """
    destino.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archivo_tar, "r:*") as tar:
        miembros = [
            m for m in tar.getmembers()
            if m.isfile() and not Path(m.name).name.startswith(("cmds", "."))
        ]
        miembros.sort(key=lambda m: m.name)
        elegidos = random.Random(SEMILLA).sample(miembros, min(cantidad, len(miembros)))
        guardados = []
        for miembro in elegidos:
            try:
                miembro = tarfile.data_filter(miembro, str(destino))
            except tarfile.FilterError:
                consola.print(f"[yellow]Descartado un elemento peligroso del tar:[/yellow] {miembro.name!r}")
                continue
            contenido = tar.extractfile(miembro).read()
            ruta = destino / f"spamassassin-{Path(miembro.name).name.split('.')[0]}.eml"
            ruta.write_bytes(contenido)
            guardados.append(ruta)
    return guardados


def descargar_legitimos(cantidad: int, destino: Path, sesion=None) -> list[Path]:
    sesion = sesion or requests.Session()
    descargas = CARPETA / "descargas"
    descargas.mkdir(parents=True, exist_ok=True)
    archivo = descargas / Path(URL_HAM).name
    if not archivo.exists():
        consola.print("Descargando el corpus de SpamAssassin...")
        respuesta = sesion.get(URL_HAM, timeout=60)
        respuesta.raise_for_status()
        archivo.write_bytes(respuesta.content)
    return extraer_legitimos(archivo, cantidad, destino)


def escribir_manifiesto(filas: list[dict], ruta: Path) -> None:
    """Lista de correos con su etiqueta, fuente y hash: documenta exactamente qué se evaluó."""
    with ruta.open("w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=["fichero", "etiqueta", "fuente", "sha256"])
        escritor.writeheader()
        escritor.writerows(filas)


def main() -> int:
    argumentos = argparse.ArgumentParser(description="Prepara el corpus de evaluación")
    argumentos.add_argument("--phishing", type=int, default=100, help="número de correos de phishing")
    argumentos.add_argument("--legitimos", type=int, default=100, help="número de correos legítimos")
    args = argumentos.parse_args()

    filas = []
    consola.print(f"[bold]Descargando {args.phishing} correos de phishing de Phishing Pot...[/bold]")
    for ruta in descargar_phishing(args.phishing, CARPETA / "phishing"):
        filas.append({"fichero": str(ruta.relative_to(CARPETA)), "etiqueta": "phishing",
                      "fuente": "phishing_pot", "sha256": _sha256(ruta.read_bytes())})

    consola.print(f"[bold]Extrayendo {args.legitimos} correos legítimos de SpamAssassin...[/bold]")
    try:
        legitimos = descargar_legitimos(args.legitimos, CARPETA / "legitimo")
    except requests.RequestException as exc:
        consola.print(f"[red]No se pudo descargar el corpus de SpamAssassin:[/red] {exc}")
        legitimos = []
    for ruta in legitimos:
        filas.append({"fichero": str(ruta.relative_to(CARPETA)), "etiqueta": "legitimo",
                      "fuente": "spamassassin_easy_ham", "sha256": _sha256(ruta.read_bytes())})

    propios = sorted((CARPETA / "legitimo_propio").glob("*.eml"))
    for ruta in propios:
        filas.append({"fichero": str(ruta.relative_to(CARPETA)), "etiqueta": "legitimo",
                      "fuente": "propio", "sha256": _sha256(ruta.read_bytes())})

    escribir_manifiesto(filas, CARPETA / "manifiesto.csv")
    total_phishing = sum(1 for f in filas if f["etiqueta"] == "phishing")
    consola.print(f"\n[green]Corpus listo:[/green] {total_phishing} de phishing, "
                  f"{len(legitimos)} legítimos de SpamAssassin y {len(propios)} legítimos propios.")
    consola.print(f"Manifiesto: {(CARPETA / 'manifiesto.csv').relative_to(RAIZ_PROYECTO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
