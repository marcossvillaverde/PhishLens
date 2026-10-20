"""
Comprobaciones heurísticas deterministas sobre el remitente, las URLs y los adjuntos.

Son reglas fijas: dado el mismo correo, siempre dan el mismo resultado.
No hacen ninguna conexión de red.
"""

import ipaddress
from pathlib import PurePosixPath
from urllib.parse import urlparse

from phishlens.checks.modelos import (
    Hallazgo,
    Severidad,
    dominio_de_correo,
    dominio_organizativo,
)
from phishlens.parser import CorreoParseado

# Marcas suplantadas con frecuencia (nombre -> dominios oficiales)
MARCAS = {
    "paypal": ["paypal.com", "paypal.es"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "office365": ["office.com", "microsoft.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.es"],
    "netflix": ["netflix.com"],
    "bbva": ["bbva.es", "bbva.com"],
    "santander": ["bancosantander.es", "santander.com"],
    "caixabank": ["caixabank.es", "caixabank.com"],
    "correos": ["correos.es"],
    "dhl": ["dhl.com", "dhl.es"],
    "agenciatributaria": ["agenciatributaria.gob.es", "agenciatributaria.es"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "facebookmail.com"],
}

# Proveedores de correo gratuito (un banco nunca responde desde aquí)
CORREO_GRATUITO = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.es",
    "live.com", "yahoo.com", "yahoo.es", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "aol.com", "mail.com",
}

# Acortadores de URL: ocultan el destino real
ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly",
}

# Extensiones de adjunto que pueden ejecutar código
EXTENSIONES_PELIGROSAS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".msi", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".lnk", ".jar", ".iso", ".img",
    ".html", ".htm", ".svg", ".docm", ".xlsm", ".pptm", ".one",
}

# Sustituciones típicas para imitar letras (homoglifos)
HOMOGLIFOS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "rn": "m", "vv": "w"}


def _distancia_levenshtein(a: str, b: str) -> int:
    """Número mínimo de cambios (insertar, borrar, sustituir) para pasar de a a b."""
    if len(a) < len(b):
        a, b = b, a
    anterior = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        actual = [i]
        for j, cb in enumerate(b, 1):
            actual.append(min(anterior[j] + 1, actual[j - 1] + 1, anterior[j - 1] + (ca != cb)))
        anterior = actual
    return anterior[-1]


def _normalizar_homoglifos(texto: str) -> str:
    """Deshace las sustituciones típicas: paypa1 -> paypal, rnicrosoft -> microsoft."""
    for falso, real in HOMOGLIFOS.items():
        texto = texto.replace(falso, real)
    return texto


def detectar_suplantacion_dominio(dominio: str) -> str | None:
    """
    Comprueba si un dominio imita a una marca conocida sin ser oficial.

    Devuelve el nombre de la marca imitada o None.
    Ejemplos que detecta: paypa1-verify.com, micros0ft.com, secure-bbva.net
    Limitación conocida: no detecta la marca pegada a otra palabra
    (paypalsecure.com), para no marcar empresas legítimas como correosexpress.com.
    """
    dominio_org = dominio_organizativo(dominio)
    if not dominio_org:
        return None
    oficiales = {d for lista in MARCAS.values() for d in lista}
    if dominio_org in oficiales:
        return None

    # Nombre del dominio sin sufijo, p. ej. "paypa1-verify"
    nombre = dominio_org.split(".")[0]
    nombre_normalizado = _normalizar_homoglifos(nombre)
    partes = nombre_normalizado.replace("_", "-").split("-")

    for marca in MARCAS:
        for parte in partes:
            # 1. La marca aparece como palabra separada (paypal-seguro, secure-bbva, paypa1-verify)
            if parte == marca:
                return marca
            # 2. Una palabra se parece mucho a la marca (paypall, gooogle).
            #    Solo con marcas de 5 o más letras para evitar falsos positivos.
            if len(marca) >= 5 and _distancia_levenshtein(parte, marca) <= 1:
                return marca
    return None


def _es_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def comprobar_remitente(correo: CorreoParseado) -> list[Hallazgo]:
    """Busca incoherencias y suplantaciones en las direcciones del remitente."""
    hallazgos: list[Hallazgo] = []
    dominio_from = dominio_de_correo(correo.remitente)
    org_from = dominio_organizativo(dominio_from)

    # Reply-To distinto del From: las respuestas irían a otra persona
    if correo.reply_to:
        dominio_reply = dominio_de_correo(correo.reply_to)
        if dominio_organizativo(dominio_reply) != org_from:
            # A un correo gratuito: indicio fuerte. A otro dominio: habitual en listas de correo
            # y envíos de marketing legítimos, así que es un indicio débil
            severidad = Severidad.ALTA if dominio_reply in CORREO_GRATUITO else Severidad.BAJA
            hallazgos.append(Hallazgo(
                "REPLY_TO_DISTINTO", "remitente", severidad,
                "Las respuestas a este correo irían a un dominio distinto del remitente"
                + (" (un proveedor de correo gratuito)." if dominio_reply in CORREO_GRATUITO else "."),
                f"From: {correo.remitente} / Reply-To: {correo.reply_to}",
            ))

    # Return-Path distinto del From: el "remitente de sobre" es otro
    if correo.return_path:
        if dominio_organizativo(dominio_de_correo(correo.return_path)) != org_from:
            hallazgos.append(Hallazgo(
                "RETURN_PATH_DISTINTO", "remitente", Severidad.BAJA,
                "El remitente técnico (Return-Path) no coincide con el remitente visible. "
                "Es habitual en envíos masivos legítimos, pero también en suplantaciones.",
                f"From: {correo.remitente} / Return-Path: {correo.return_path}",
            ))

    # El nombre visible cita una marca pero el dominio no es suyo
    nombre_visible = correo.remitente_nombre.lower().replace(" ", "")
    for marca, oficiales in MARCAS.items():
        if marca in nombre_visible and org_from not in oficiales:
            hallazgos.append(Hallazgo(
                "NOMBRE_SUPLANTA_MARCA", "remitente", Severidad.ALTA,
                f"El nombre del remitente menciona a '{marca}', pero el correo no viene de un dominio oficial.",
                f"{correo.remitente_nombre} <{correo.remitente}>",
            ))
            break

    # El propio dominio del remitente imita a una marca
    marca = detectar_suplantacion_dominio(dominio_from)
    if marca:
        hallazgos.append(Hallazgo(
            "DOMINIO_REMITENTE_SIMILAR", "remitente", Severidad.ALTA,
            f"El dominio del remitente imita a '{marca}' sin ser oficial.",
            dominio_from,
        ))

    return hallazgos


def comprobar_urls(correo: CorreoParseado) -> list[Hallazgo]:
    """Analiza los enlaces del correo."""
    hallazgos: list[Hallazgo] = []

    for url in correo.urls:
        host = (urlparse(url.url).hostname or "").lower()

        # El texto visible muestra un dominio y el enlace lleva a otro
        if url.texto_visible:
            texto = url.texto_visible.strip().lower()
            if not texto.startswith(("http://", "https://")) and "." in texto and " " not in texto:
                texto = "http://" + texto
            host_visible = (urlparse(texto).hostname or "") if texto.startswith("http") else ""
            if host_visible and dominio_organizativo(host_visible) != dominio_organizativo(host):
                hallazgos.append(Hallazgo(
                    "URL_TEXTO_ENGANOSO", "urls", Severidad.CRITICA,
                    "El texto del enlace muestra una dirección, pero lleva a otra distinta.",
                    f"Muestra {host_visible} -> lleva a {host}",
                ))

        # Dominio que imita a una marca
        marca = detectar_suplantacion_dominio(host)
        if marca:
            hallazgos.append(Hallazgo(
                "URL_DOMINIO_SIMILAR", "urls", Severidad.ALTA,
                f"El enlace apunta a un dominio que imita a '{marca}'.",
                host,
            ))

        # Enlace a una IP en lugar de a un dominio
        if _es_ip(host):
            hallazgos.append(Hallazgo(
                "URL_IP_DIRECTA", "urls", Severidad.MEDIA,
                "El enlace apunta directamente a una dirección IP, algo poco habitual en servicios legítimos.",
                url.url,
            ))

        # Acortador que oculta el destino
        if dominio_organizativo(host) in ACORTADORES:
            hallazgos.append(Hallazgo(
                "URL_ACORTADA", "urls", Severidad.MEDIA,
                "El enlace usa un acortador que oculta el destino real.",
                url.url,
            ))

        # Enlace sin cifrar (http)
        if url.url.lower().startswith("http://"):
            hallazgos.append(Hallazgo(
                "URL_SIN_HTTPS", "urls", Severidad.BAJA,
                "El enlace no usa HTTPS.",
                url.url,
            ))

    return hallazgos


def comprobar_adjuntos(correo: CorreoParseado) -> list[Hallazgo]:
    """Analiza nombres y tipos de los adjuntos (sin abrirlos)."""
    hallazgos: list[Hallazgo] = []

    for adjunto in correo.adjuntos:
        nombre = adjunto.nombre.lower()
        extensiones = PurePosixPath(nombre).suffixes

        if extensiones and extensiones[-1] in EXTENSIONES_PELIGROSAS:
            hallazgos.append(Hallazgo(
                "ADJUNTO_PELIGROSO", "adjuntos", Severidad.ALTA,
                f"El adjunto tiene una extensión que puede ejecutar código ({extensiones[-1]}).",
                adjunto.nombre,
            ))

        # Doble extensión: factura.pdf.exe
        if len(extensiones) >= 2 and extensiones[-1] in EXTENSIONES_PELIGROSAS:
            hallazgos.append(Hallazgo(
                "ADJUNTO_DOBLE_EXTENSION", "adjuntos", Severidad.CRITICA,
                "El adjunto usa doble extensión para parecer un documento inofensivo.",
                adjunto.nombre,
            ))

    return hallazgos


def comprobar_heuristicas(correo: CorreoParseado) -> list[Hallazgo]:
    """Ejecuta todas las comprobaciones heurísticas."""
    return comprobar_remitente(correo) + comprobar_urls(correo) + comprobar_adjuntos(correo)
