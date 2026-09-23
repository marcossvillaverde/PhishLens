"""
Módulo de parseo de correos (.eml).

Descompone un correo en bruto en sus partes: cabeceras, cadena de servidores
(Received), cuerpo en texto y HTML, URLs y adjuntos. No abre ni ejecuta
ningún adjunto: solo calcula sus hashes.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from bs4 import BeautifulSoup

# Expresión regular para encontrar URLs en texto plano
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Expresiones regulares para encontrar IPs en las cabeceras Received
IPV4_REGEX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
IPV6_REGEX = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,})\]")

# Redes internas: una IP de estas redes nunca es el origen real del correo
REDES_INTERNAS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class Url:
    """Una URL encontrada en el correo."""
    url: str                  # destino real del enlace
    texto_visible: str = ""   # texto que ve el usuario (solo en enlaces HTML)
    origen: str = "texto"     # "html" o "texto"


@dataclass
class Adjunto:
    """Un fichero adjunto (nunca se guarda en disco ni se ejecuta)."""
    nombre: str
    tipo_mime: str
    tamano: int
    md5: str
    sha256: str


@dataclass
class CorreoParseado:
    """Resultado del parseo de un correo."""
    remitente: str = ""            # dirección de la cabecera From
    remitente_nombre: str = ""     # nombre mostrado en From
    destinatarios: list[str] = field(default_factory=list)
    asunto: str = ""
    fecha: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    received: list[str] = field(default_factory=list)   # del más reciente al más antiguo
    ip_origen: str | None = None                         # primera IP externa de la cadena
    authentication_results: str = ""
    cuerpo_texto: str = ""
    cuerpo_html: str = ""
    urls: list[Url] = field(default_factory=list)
    adjuntos: list[Adjunto] = field(default_factory=list)
    bytes_originales: bytes = b""                        # necesario para verificar DKIM


def _es_ip_interna(ip_texto: str) -> bool:
    """Devuelve True si la IP pertenece a una red interna o no es válida."""
    try:
        ip = ipaddress.ip_address(ip_texto)
    except ValueError:
        return True
    return any(ip in red for red in REDES_INTERNAS)


def _extraer_ip_origen(received: list[str]) -> str | None:
    """
    Busca la IP del servidor que envió el correo originalmente.

    Las cabeceras Received se añaden de arriba abajo, así que la última
    de la lista es la más antigua (la más cercana al emisor). Se recorren
    desde la más antigua y se devuelve la primera IP externa encontrada.
    """
    for cabecera in reversed(received):
        # Solo interesa la parte "from ..." de la cabecera, no la parte "by ..."
        parte_from = cabecera.split(" by ")[0]
        candidatas = IPV6_REGEX.findall(parte_from) + IPV4_REGEX.findall(parte_from)
        for ip in candidatas:
            if not _es_ip_interna(ip):
                return ip
    return None


def _leer_contenido(parte: EmailMessage) -> str:
    """Obtiene el texto de una parte del correo tolerando codificaciones rotas."""
    try:
        return parte.get_content()
    except (LookupError, UnicodeDecodeError, KeyError):
        datos = parte.get_payload(decode=True) or b""
        return datos.decode("utf-8", errors="replace")


def _extraer_urls(texto: str, html: str) -> list[Url]:
    """Extrae las URLs del HTML (con su texto visible) y del texto plano, sin duplicados."""
    encontradas: dict[str, Url] = {}

    # 1. Enlaces del HTML: interesa comparar el destino real con el texto visible
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for enlace in soup.find_all("a", href=True):
            destino = enlace["href"].strip()
            if destino.lower().startswith(("http://", "https://")):
                encontradas.setdefault(
                    destino,
                    Url(url=destino, texto_visible=enlace.get_text(strip=True), origen="html"),
                )
        # URLs sueltas dentro del HTML (texto sin etiqueta <a>).
        # Se quitan antes los enlaces para no confundir su texto visible
        # (que puede ser una URL falsa) con un destino real.
        for enlace in soup.find_all("a"):
            enlace.decompose()
        for destino in URL_REGEX.findall(soup.get_text(" ")):
            encontradas.setdefault(destino, Url(url=destino, origen="html"))

    # 2. URLs del texto plano
    for destino in URL_REGEX.findall(texto):
        encontradas.setdefault(destino, Url(url=destino, origen="texto"))

    return list(encontradas.values())


def _procesar_adjunto(parte: EmailMessage) -> Adjunto:
    """Calcula los datos y hashes de un adjunto sin guardarlo ni abrirlo."""
    datos = parte.get_payload(decode=True) or b""
    return Adjunto(
        nombre=parte.get_filename() or "(sin nombre)",
        tipo_mime=parte.get_content_type(),
        tamano=len(datos),
        md5=hashlib.md5(datos).hexdigest(),
        sha256=hashlib.sha256(datos).hexdigest(),
    )


def parsear_bytes(datos: bytes) -> CorreoParseado:
    """Parsea un correo a partir de sus bytes en bruto."""
    mensaje: EmailMessage = BytesParser(policy=policy.default).parsebytes(datos)
    correo = CorreoParseado(bytes_originales=datos)

    # --- Cabeceras principales ---
    correo.remitente_nombre, correo.remitente = parseaddr(str(mensaje.get("From", "")))
    correo.destinatarios = [
        direccion for _, direccion in getaddresses(
            [str(v) for v in mensaje.get_all("To", []) + mensaje.get_all("Cc", [])]
        ) if direccion
    ]
    correo.asunto = str(mensaje.get("Subject", ""))
    correo.fecha = str(mensaje.get("Date", ""))
    correo.reply_to = parseaddr(str(mensaje.get("Reply-To", "")))[1]
    correo.return_path = parseaddr(str(mensaje.get("Return-Path", "")))[1]
    correo.message_id = str(mensaje.get("Message-ID", ""))
    correo.authentication_results = str(mensaje.get("Authentication-Results", ""))

    # --- Cadena de servidores ---
    correo.received = [" ".join(str(r).split()) for r in mensaje.get_all("Received", [])]
    correo.ip_origen = _extraer_ip_origen(correo.received)

    # --- Cuerpo y adjuntos ---
    textos, htmls = [], []
    for parte in mensaje.walk():
        if parte.is_multipart():
            continue
        if parte.get_content_disposition() == "attachment" or parte.get_filename():
            correo.adjuntos.append(_procesar_adjunto(parte))
        elif parte.get_content_type() == "text/plain":
            textos.append(_leer_contenido(parte))
        elif parte.get_content_type() == "text/html":
            htmls.append(_leer_contenido(parte))

    correo.cuerpo_texto = "\n".join(textos).strip()
    correo.cuerpo_html = "\n".join(htmls).strip()
    correo.urls = _extraer_urls(correo.cuerpo_texto, correo.cuerpo_html)

    return correo


def parsear_eml(ruta: str | Path) -> CorreoParseado:
    """Lee un fichero .eml del disco y lo parsea."""
    return parsear_bytes(Path(ruta).read_bytes())
