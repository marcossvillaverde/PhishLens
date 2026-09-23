"""
Orquesta las consultas de reputación de un correo y las convierte en hallazgos.

Qué se consulta:
  - VirusTotal: URLs, dominios de las URLs y hashes de los adjuntos.
  - AbuseIPDB: IP del servidor que envió el correo.
  - urlscan.io: escaneos previos de los dominios (solo informativo).

Si un servicio no está configurado o falla, se registra un hallazgo
informativo y el análisis continúa con el resto.
"""

import time
from urllib.parse import urlparse

from phishlens.checks.modelos import Hallazgo, Severidad, dominio_organizativo
from phishlens.config import Config
from phishlens.enrichment.abuseipdb import ClienteAbuseIPDB
from phishlens.enrichment.base import Cache, ResultadoReputacion
from phishlens.enrichment.urlscan import ClienteUrlscan
from phishlens.enrichment.virustotal import ClienteVirusTotal
from phishlens.parser import CorreoParseado

# Límites por correo para no agotar la cuota gratuita (VirusTotal: 4 por minuto)
MAX_URLS = 3
MAX_DOMINIOS = 2
MAX_ADJUNTOS = 3

# Umbrales de detección
MOTORES_CRITICO = 3        # 3 o más antivirus lo marcan como malicioso
DIAS_DOMINIO_RECIENTE = 30
ABUSO_ALTO = 50            # puntuación de AbuseIPDB (0-100)
ABUSO_MEDIO = 10


def _sin_duplicados(elementos: list[str]) -> list[str]:
    return list(dict.fromkeys(e for e in elementos if e))


def _hallazgo_error(resultado: ResultadoReputacion) -> Hallazgo:
    return Hallazgo(
        "REPUTACION_NO_DISPONIBLE", "reputacion", Severidad.INFO,
        f"No se pudo consultar {resultado.servicio}: {resultado.error}.",
        resultado.indicador,
    )


def _hallazgos_virustotal(resultado: ResultadoReputacion, ahora: float) -> list[Hallazgo]:
    if resultado.error:
        return [_hallazgo_error(resultado)]
    if not resultado.encontrado:
        return []

    hallazgos = []
    maliciosos = resultado.datos.get("maliciosos", 0)
    nombres = {"url": "La URL", "hash": "El adjunto", "dominio": "El dominio"}
    codigos = {"url": "URL", "hash": "ADJUNTO", "dominio": "DOMINIO"}
    evidencia = f"{resultado.indicador} ({maliciosos} motores lo marcan como malicioso)"

    if maliciosos >= MOTORES_CRITICO:
        hallazgos.append(Hallazgo(
            f"{codigos[resultado.tipo]}_MALICIOSO_VT", "reputacion", Severidad.CRITICA,
            f"{nombres[resultado.tipo]} está catalogado como malicioso por varios motores de VirusTotal.",
            evidencia,
        ))
    elif maliciosos >= 1 or resultado.datos.get("sospechosos", 0) >= 2:
        hallazgos.append(Hallazgo(
            f"{codigos[resultado.tipo]}_SOSPECHOSO_VT", "reputacion", Severidad.ALTA,
            f"{nombres[resultado.tipo]} tiene alguna detección en VirusTotal.",
            evidencia,
        ))

    creacion = resultado.datos.get("fecha_creacion")
    if resultado.tipo == "dominio" and creacion:
        dias = int((ahora - creacion) // 86400)
        if 0 <= dias < DIAS_DOMINIO_RECIENTE:
            hallazgos.append(Hallazgo(
                "DOMINIO_RECIENTE", "reputacion", Severidad.ALTA,
                f"El dominio se registró hace solo {dias} días; los dominios de phishing suelen ser muy recientes.",
                resultado.indicador,
            ))
    return hallazgos


def _hallazgos_abuseipdb(resultado: ResultadoReputacion) -> list[Hallazgo]:
    if resultado.error:
        return [_hallazgo_error(resultado)]
    if not resultado.encontrado or resultado.datos.get("en_lista_blanca"):
        return []
    puntuacion = resultado.datos.get("puntuacion_abuso", 0)
    evidencia = (f"{resultado.indicador}: puntuación {puntuacion}/100, "
                 f"{resultado.datos.get('total_reportes', 0)} reportes, país {resultado.datos.get('pais') or '?'}")
    if puntuacion >= ABUSO_ALTO:
        return [Hallazgo("IP_ORIGEN_REPORTADA", "reputacion", Severidad.ALTA,
                         "La IP que envió el correo tiene numerosas denuncias por actividad maliciosa.", evidencia)]
    if puntuacion >= ABUSO_MEDIO:
        return [Hallazgo("IP_ORIGEN_CON_REPORTES", "reputacion", Severidad.MEDIA,
                         "La IP que envió el correo tiene algunas denuncias por actividad maliciosa.", evidencia)]
    return []


def _hallazgos_urlscan(resultado: ResultadoReputacion) -> list[Hallazgo]:
    if resultado.error:
        return [_hallazgo_error(resultado)]
    if not resultado.encontrado:
        return []
    return [Hallazgo(
        "URLSCAN_HISTORIAL", "reputacion", Severidad.INFO,
        f"urlscan.io tiene {resultado.datos['escaneos_previos']} escaneos previos de este dominio.",
        resultado.datos.get("ultimo_informe", resultado.indicador),
    )]


def enriquecer(
    correo: CorreoParseado,
    config: Config,
    virustotal: ClienteVirusTotal | None = None,
    abuseipdb: ClienteAbuseIPDB | None = None,
    urlscan: ClienteUrlscan | None = None,
    reloj=time.time,
) -> tuple[list[ResultadoReputacion], list[Hallazgo]]:
    """
    Consulta la reputación de los indicadores del correo.

    Los clientes se pueden inyectar (útil en las pruebas); si no se pasan,
    se crean a partir de la configuración.
    """
    cache = Cache(config.carpeta_cache)
    resultados: list[ResultadoReputacion] = []
    hallazgos: list[Hallazgo] = []
    ahora = reloj()

    urls = _sin_duplicados([u.url for u in correo.urls])[:MAX_URLS]
    dominios = _sin_duplicados(
        [dominio_organizativo((urlparse(u).hostname or "").lower()) for u in urls]
    )[:MAX_DOMINIOS]
    hashes = _sin_duplicados([a.sha256 for a in correo.adjuntos])[:MAX_ADJUNTOS]

    # --- VirusTotal ---
    if virustotal is None and config.virustotal_api_key:
        virustotal = ClienteVirusTotal(config.virustotal_api_key, cache)
    if virustotal is None:
        if urls or hashes:
            hallazgos.append(Hallazgo("REPUTACION_NO_CONFIGURADA", "reputacion", Severidad.INFO,
                                      "VirusTotal no está configurado (falta VIRUSTOTAL_API_KEY)."))
    else:
        consultas = ([virustotal.consultar_url(u) for u in urls]
                     + [virustotal.consultar_dominio(d) for d in dominios]
                     + [virustotal.consultar_hash(h) for h in hashes])
        for r in consultas:
            resultados.append(r)
            hallazgos += _hallazgos_virustotal(r, ahora)

    # --- AbuseIPDB ---
    if correo.ip_origen:
        if abuseipdb is None and config.abuseipdb_api_key:
            abuseipdb = ClienteAbuseIPDB(config.abuseipdb_api_key, cache)
        if abuseipdb is None:
            hallazgos.append(Hallazgo("REPUTACION_NO_CONFIGURADA", "reputacion", Severidad.INFO,
                                      "AbuseIPDB no está configurado (falta ABUSEIPDB_API_KEY)."))
        else:
            r = abuseipdb.consultar_ip(correo.ip_origen)
            resultados.append(r)
            hallazgos += _hallazgos_abuseipdb(r)

    # --- urlscan.io (informativo) ---
    if dominios:
        if urlscan is None and config.urlscan_api_key:
            urlscan = ClienteUrlscan(config.urlscan_api_key, cache)
        if urlscan is not None:
            for d in dominios:
                r = urlscan.buscar_dominio(d)
                resultados.append(r)
                hallazgos += _hallazgos_urlscan(r)

    return resultados, hallazgos
