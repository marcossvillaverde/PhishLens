"""
Cliente de VirusTotal (API v3).

Solo CONSULTA indicadores ya analizados: nunca sube URLs ni ficheros,
porque subirlos los haría públicos y podría alertar al atacante.
La API pública permite 4 peticiones por minuto.
"""

import base64

import requests

from phishlens.enrichment.base import Cache, LimitadorCuota, ResultadoReputacion, mensaje_http, peticion_get

URL_BASE = "https://www.virustotal.com/api/v3"


def _id_url(url: str) -> str:
    """VirusTotal identifica cada URL por su codificación base64 URL-safe sin '='."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class ClienteVirusTotal:
    def __init__(self, api_key: str, cache: Cache, sesion: requests.Session | None = None,
                 limitador: LimitadorCuota | None = None):
        self.api_key = api_key
        self.cache = cache
        self.sesion = sesion or requests.Session()
        self.limitador = limitador or LimitadorCuota(maximo=4, ventana=60)

    def _consultar(self, tipo: str, indicador: str, ruta: str) -> ResultadoReputacion:
        resultado = ResultadoReputacion(servicio="virustotal", tipo=tipo, indicador=indicador)
        clave_cache = f"virustotal:{tipo}:{indicador}"

        guardado = self.cache.obtener(clave_cache)
        if guardado is not None:
            resultado.encontrado = guardado["encontrado"]
            resultado.datos = guardado["datos"]
            resultado.desde_cache = True
            return resultado

        self.limitador.esperar_turno()
        codigo, cuerpo, error = peticion_get(self.sesion, f"{URL_BASE}/{ruta}", {"x-apikey": self.api_key})

        if error:
            resultado.error = error
            return resultado
        if codigo == 404:
            # VirusTotal no conoce el indicador: no es malo ni bueno, simplemente no hay datos
            self.cache.guardar(clave_cache, {"encontrado": False, "datos": {}})
            return resultado
        if codigo != 200 or not cuerpo:
            resultado.error = mensaje_http("VirusTotal", codigo)
            return resultado

        atributos = cuerpo.get("data", {}).get("attributes", {})
        estadisticas = atributos.get("last_analysis_stats", {})
        resultado.encontrado = True
        resultado.datos = {
            "maliciosos": estadisticas.get("malicious", 0),
            "sospechosos": estadisticas.get("suspicious", 0),
            "inofensivos": estadisticas.get("harmless", 0),
            "sin_deteccion": estadisticas.get("undetected", 0),
        }
        if tipo == "dominio" and atributos.get("creation_date"):
            resultado.datos["fecha_creacion"] = atributos["creation_date"]   # marca de tiempo Unix
        self.cache.guardar(clave_cache, {"encontrado": True, "datos": resultado.datos})
        return resultado

    def consultar_url(self, url: str) -> ResultadoReputacion:
        return self._consultar("url", url, f"urls/{_id_url(url)}")

    def consultar_hash(self, sha256: str) -> ResultadoReputacion:
        return self._consultar("hash", sha256, f"files/{sha256}")

    def consultar_dominio(self, dominio: str) -> ResultadoReputacion:
        return self._consultar("dominio", dominio, f"domains/{dominio}")
