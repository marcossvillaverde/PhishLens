"""
Cliente de AbuseIPDB (API v2): reputación de la IP que envió el correo.
El plan gratuito permite 1.000 consultas al día.
"""

import requests

from phishlens.enrichment.base import Cache, ResultadoReputacion, mensaje_http, peticion_get

URL_CHECK = "https://api.abuseipdb.com/api/v2/check"


class ClienteAbuseIPDB:
    def __init__(self, api_key: str, cache: Cache, sesion: requests.Session | None = None):
        self.api_key = api_key
        self.cache = cache
        self.sesion = sesion or requests.Session()

    def consultar_ip(self, ip: str) -> ResultadoReputacion:
        resultado = ResultadoReputacion(servicio="abuseipdb", tipo="ip", indicador=ip)
        clave_cache = f"abuseipdb:ip:{ip}"

        guardado = self.cache.obtener(clave_cache)
        if guardado is not None:
            resultado.encontrado, resultado.datos, resultado.desde_cache = True, guardado, True
            return resultado

        codigo, cuerpo, error = peticion_get(
            self.sesion, URL_CHECK,
            {"Key": self.api_key, "Accept": "application/json"},
            {"ipAddress": ip, "maxAgeInDays": 90},
        )
        if error:
            resultado.error = error
            return resultado
        if codigo != 200 or not cuerpo or "data" not in cuerpo:
            resultado.error = mensaje_http("AbuseIPDB", codigo)
            return resultado

        datos = cuerpo["data"]
        resultado.encontrado = True
        resultado.datos = {
            "puntuacion_abuso": datos.get("abuseConfidenceScore", 0),   # 0-100
            "total_reportes": datos.get("totalReports", 0),
            "pais": datos.get("countryCode") or "",
            "proveedor": datos.get("isp") or "",
            "en_lista_blanca": bool(datos.get("isWhitelisted")),
        }
        self.cache.guardar(clave_cache, resultado.datos)
        return resultado
