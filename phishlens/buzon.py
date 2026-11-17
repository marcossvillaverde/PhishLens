"""
Vigilancia de un buzón de correo por IMAP (hito H10, prototipo).

Revisa periódicamente la bandeja de entrada de una cuenta, analiza con PhishLens
los correos que han llegado desde la última revisión y les añade una etiqueta con
el veredicto (en Gmail: PhishLens/Phishing, PhishLens/Sospechoso, PhishLens/Limpio).

Decisiones de seguridad:
  - Solo lee y etiqueta. Los únicos comandos IMAP permitidos son SEARCH, FETCH y
    STORE (este último, solo para añadir la etiqueta de PhishLens). Nunca borra,
    mueve, copia ni envía correos: _uid() rechaza cualquier otro comando.
  - Descarga con BODY.PEEK[], que no marca los correos como leídos.
  - Credencial en .env (contraseña de aplicación revocable), nunca en el código ni
    en la salida.
  - Reputación desactivada por defecto: los enlaces del correo personal no se
    envían a servicios externos salvo que se pida con --con-reputacion.
  - En la primera ejecución no analiza los correos que ya había: anota el último
    y solo procesa los que lleguen después (salvo --ultimos N).
  - Modo --prueba: abre el buzón en solo lectura, no etiqueta y no guarda el estado.

Configuración en .env:
    IMAP_SERVIDOR=imap.gmail.com
    IMAP_USUARIO=cuenta@gmail.com
    IMAP_CONTRASENA=contraseña de aplicación de 16 letras

Uso:
    python -m phishlens.buzon --prueba --una-vez     (prueba sin tocar el buzón)
    python -m phishlens.buzon --una-vez              (una revisión)
    python -m phishlens.buzon --intervalo 2          (vigilancia continua cada 2 minutos)
"""

import argparse
import contextlib
import hashlib
import imaplib
import json
import os
import re
import ssl
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markup import escape

from phishlens.analisis import OpcionesAnalisis, analizar
from phishlens.config import RAIZ_PROYECTO, cargar_config
from phishlens.report import guardar_informes

consola = Console()

CARPETA_ESTADO = RAIZ_PROYECTO / ".cache"
CARPETA_INFORMES = RAIZ_PROYECTO / "reports" / "buzon"
TAMANO_MAXIMO = 20 * 1024 * 1024        # correos más grandes no se descargan
TIMEOUT = 30

ETIQUETAS_GMAIL = {"phishing": "PhishLens/Phishing", "sospechoso": "PhishLens/Sospechoso",
                   "limpio": "PhishLens/Limpio"}

# Lista blanca de comandos IMAP (por UID). Cualquier otro se rechaza.
COMANDOS_PERMITIDOS = {"SEARCH", "FETCH", "STORE"}
# Únicas modificaciones permitidas con STORE: añadir la etiqueta de PhishLens
STORE_PERMITIDO = re.compile(r'^\+X-GM-LABELS$|^\+FLAGS$')
VALOR_STORE_PERMITIDO = re.compile(r'^\("PhishLens/(Phishing|Sospechoso|Limpio)"\)$|^\(PhishLens_(phishing|sospechoso|limpio)\)$')


class ErrorBuzon(Exception):
    pass


@dataclass
class CorreoRevisado:
    uid: int
    veredicto: str = ""
    remitente: str = ""
    asunto: str = ""
    etiqueta: str = ""
    error: str = ""


# ---------------------------------------------------------------- IMAP seguro

def _uid(conexion, comando: str, *args):
    """Ejecuta un comando IMAP por UID solo si está en la lista blanca."""
    comando = comando.upper()
    if comando not in COMANDOS_PERMITIDOS:
        raise ErrorBuzon(f"comando IMAP no permitido: {comando}")
    if comando == "FETCH" and "BODY[" in args[1].upper() and "BODY.PEEK[" not in args[1].upper():
        raise ErrorBuzon("solo se permite BODY.PEEK[] (no marcar como leído)")
    if comando == "STORE" and not (STORE_PERMITIDO.match(args[1]) and VALOR_STORE_PERMITIDO.match(args[2])):
        raise ErrorBuzon(f"modificación no permitida: {args[1]} {args[2]}")
    estado, datos = conexion.uid(comando, *args)
    if estado != "OK":
        raise ErrorBuzon(f"el servidor rechazó {comando}: {datos!r}"[:200])
    return datos


def _buscar(conexion, desde_uid: int | None = None) -> list[int]:
    criterio = ("UID", f"{desde_uid}:*") if desde_uid else ("ALL",)
    datos = _uid(conexion, "SEARCH", None, *criterio)
    uids = sorted(int(u) for u in (datos[0] or b"").split())
    # IMAP devuelve el último correo aunque su UID sea menor que el rango pedido
    return [u for u in uids if desde_uid is None or u >= desde_uid]


def _tamano(conexion, uid: int) -> int:
    datos = _uid(conexion, "FETCH", str(uid), "(RFC822.SIZE)")
    encontrado = re.search(rb"RFC822\.SIZE (\d+)", datos[0] or b"")
    return int(encontrado.group(1)) if encontrado else 0


def _descargar(conexion, uid: int) -> bytes:
    datos = _uid(conexion, "FETCH", str(uid), "(BODY.PEEK[])")
    for parte in datos:
        if isinstance(parte, tuple) and len(parte) == 2:
            return parte[1]
    raise ErrorBuzon(f"respuesta FETCH sin contenido para el UID {uid}")


def _etiquetar(conexion, uid: int, veredicto: str) -> str:
    if "X-GM-EXT-1" in getattr(conexion, "capabilities", ()):
        etiqueta = ETIQUETAS_GMAIL[veredicto]
        _uid(conexion, "STORE", str(uid), "+X-GM-LABELS", f'("{etiqueta}")')
    else:  # servidores IMAP genéricos: palabra clave en el correo
        etiqueta = f"PhishLens_{veredicto}"
        _uid(conexion, "STORE", str(uid), "+FLAGS", f"({etiqueta})")
    return etiqueta


def _uidvalidity(conexion) -> str:
    _, datos = conexion.response("UIDVALIDITY")
    return (datos[0] or b"").decode() if datos and datos[0] else ""


# ---------------------------------------------------------------- estado

def ruta_estado(usuario: str) -> Path:
    """Fichero de estado por cuenta. El nombre usa un hash: no deja la dirección a la vista."""
    huella = hashlib.sha256(usuario.strip().lower().encode()).hexdigest()[:16]
    return CARPETA_ESTADO / f"buzon_{huella}.json"


def leer_estado(ruta: Path) -> dict | None:
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def guardar_estado(ruta: Path, estado: dict) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".tmp")
    temporal.write_text(json.dumps(estado), encoding="utf-8")
    temporal.chmod(0o600)
    temporal.replace(ruta)


# ---------------------------------------------------------------- revisión

def revisar(conexion, fichero_estado: Path, analizador: Callable[[Path], object], prueba: bool = False,
            ultimos: int = 0, carpeta_informes: Path | None = None) -> list[CorreoRevisado]:
    """Una revisión del buzón: analiza y etiqueta los correos nuevos."""
    estado_sel, _ = conexion.select("INBOX", readonly=prueba)
    if estado_sel != "OK":
        raise ErrorBuzon("no se pudo abrir la bandeja de entrada")
    validez = _uidvalidity(conexion)

    estado = leer_estado(fichero_estado)
    if not estado or estado.get("uidvalidity") != validez:
        # Primera ejecución (o el servidor renumeró el buzón): no se analiza lo que ya había
        todos = _buscar(conexion)
        if ultimos and todos:
            ultimo = todos[-ultimos - 1] if len(todos) > ultimos else 0
        else:
            ultimo = todos[-1] if todos else 0
        estado = {"uidvalidity": validez, "ultimo_uid": ultimo}
        if not ultimos:
            consola.print(f"[cyan]Primera revisión: {len(todos)} correos existentes se dejan sin analizar; "
                          f"se analizarán los que lleguen a partir de ahora.[/cyan]")
        if not prueba:
            guardar_estado(fichero_estado, estado)

    nuevos = _buscar(conexion, estado["ultimo_uid"] + 1)
    revisados = []
    for uid in nuevos:
        revisado = CorreoRevisado(uid=uid)
        try:
            if _tamano(conexion, uid) > TAMANO_MAXIMO:
                raise ErrorBuzon("correo demasiado grande; no se descarga")
            datos = _descargar(conexion, uid)
            # Fichero temporal privado: se borra al terminar el análisis
            with tempfile.TemporaryDirectory(prefix="phishlens_") as carpeta:
                ruta = Path(carpeta) / f"{uid}.eml"
                ruta.write_bytes(datos)
                ruta.chmod(0o600)
                resultado = analizador(ruta)
            revisado.veredicto = resultado.final.veredicto.value
            revisado.remitente = str(getattr(resultado.correo, "remitente", "") or "")
            revisado.asunto = str(getattr(resultado.correo, "asunto", "") or "")
            if carpeta_informes:
                guardar_informes(resultado, carpeta_informes)
            if not prueba:
                revisado.etiqueta = _etiquetar(conexion, uid, revisado.veredicto)
        except Exception as exc:  # noqa: BLE001 - un correo problemático no debe detener la vigilancia
            revisado.error = str(exc)[:200]
        revisados.append(revisado)
        if not prueba:
            estado["ultimo_uid"] = uid
            guardar_estado(fichero_estado, estado)
    return revisados


def mostrar(revisados: list[CorreoRevisado], prueba: bool) -> None:
    colores = {"phishing": "red", "sospechoso": "yellow", "limpio": "green"}
    if not revisados:
        consola.print(f"[dim]{time.strftime('%H:%M:%S')} Sin correos nuevos.[/dim]")
    for r in revisados:
        if r.error:
            consola.print(f"[yellow]UID {r.uid}: no analizado ({escape(r.error)})[/yellow]")
            continue
        color = colores.get(r.veredicto, "white")
        destino = "sin etiquetar (modo prueba)" if prueba else f"etiqueta {escape(r.etiqueta)}"
        consola.print(f"[{color}]{r.veredicto.upper():<10}[/{color}] UID {r.uid} · {escape(r.remitente[:50])} · "
                      f"{escape(r.asunto[:60])} → {destino}")


# ---------------------------------------------------------------- principal

def conectar(servidor: str, usuario: str, contrasena: str):
    conexion = imaplib.IMAP4_SSL(servidor, 993, ssl_context=ssl.create_default_context(), timeout=TIMEOUT)
    conexion.login(usuario, contrasena)
    return conexion


def main() -> int:
    argumentos = argparse.ArgumentParser(description="Vigila un buzón por IMAP y etiqueta los correos con PhishLens")
    argumentos.add_argument("--prueba", action="store_true", help="analizar sin modificar el buzón")
    argumentos.add_argument("--una-vez", action="store_true", help="hacer una sola revisión")
    argumentos.add_argument("--intervalo", type=float, default=5, help="minutos entre revisiones (mínimo 1)")
    argumentos.add_argument("--ultimos", type=int, default=0, help="en la primera revisión, analizar los N últimos correos existentes")
    argumentos.add_argument("--con-reputacion", action="store_true", help="consultar VirusTotal, AbuseIPDB y urlscan.io")
    argumentos.add_argument("--sin-red", action="store_true", help="no consultar el DNS (SPF, DKIM, DMARC)")
    argumentos.add_argument("--sin-ia", action="store_true", help="no usar el modelo de lenguaje")
    argumentos.add_argument("--informe", action="store_true", help="guardar informes HTML y JSON en reports/buzon/")
    args = argumentos.parse_args()

    load_dotenv(RAIZ_PROYECTO / ".env")
    servidor = os.getenv("IMAP_SERVIDOR", "imap.gmail.com")
    usuario, contrasena = os.getenv("IMAP_USUARIO"), os.getenv("IMAP_CONTRASENA")
    if not usuario or not contrasena:
        consola.print("[red]Error:[/red] faltan IMAP_USUARIO o IMAP_CONTRASENA en el fichero .env")
        return 1

    config = cargar_config()
    opciones = OpcionesAnalisis(en_linea=not args.sin_red, reputacion=args.con_reputacion, ia=not args.sin_ia)
    analizador = lambda ruta: analizar(ruta, config, opciones)
    carpeta_informes = CARPETA_INFORMES if args.informe else None
    fichero_estado = ruta_estado(usuario)
    intervalo = max(args.intervalo, 1) * 60

    modo = "PRUEBA (no se modifica el buzón)" if args.prueba else "normal (se etiquetan los correos)"
    consola.print(f"[bold]PhishLens · vigilancia de buzón[/bold] — {escape(servidor)} — modo {modo}; "
                  f"reputación {'activada' if args.con_reputacion else 'desactivada'}")
    try:
        while True:
            try:
                conexion = conectar(servidor, usuario, contrasena)
                try:
                    mostrar(revisar(conexion, fichero_estado, analizador, args.prueba, args.ultimos,
                                    carpeta_informes), args.prueba)
                finally:
                    with contextlib.suppress(imaplib.IMAP4.error, OSError):
                        conexion.logout()
            except (imaplib.IMAP4.error, OSError, ErrorBuzon) as exc:
                # El error de imaplib no incluye la contraseña; aun así se recorta
                consola.print(f"[red]Error de conexión:[/red] {escape(str(exc)[:200])}")
                if args.una_vez:
                    return 1
            if args.una_vez:
                return 0
            args.ultimos = 0          # --ultimos solo tiene sentido en la primera revisión
            proxima = time.strftime("%H:%M:%S", time.localtime(time.time() + intervalo))
            consola.print(f"[dim]Próxima revisión a las {proxima}. Ctrl+C para salir.[/dim]")
            time.sleep(intervalo)
    except KeyboardInterrupt:
        consola.print("\nVigilancia detenida.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
