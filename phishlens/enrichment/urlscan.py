"""
Cliente de urlscan.io.

Solo BUSCA escaneos anteriores de un dominio; no lanza escaneos nuevos,
porque visitar el enlace podría alertar al atacante. El resultado es
informativo: indica si el dominio ya ha sido analizado y enlaza al último informe.
"""

import requests

from phishlens.enrichment.base import Cache, ResultadoReputacion, mensaje_http, peticion_get

URL_BUSQUEDA = "https://urlscan.io/api/v1/search/"


class ClienteUrlscan:
    def __init__(self, api_key: str, cache: Cache, sesion: requests.Session | None = None):
        self.api_key = api_key
        self.cache = cache
        self.sesion = sesion or requests.Session()

    def buscar_dominio(self, dominio: str) -> ResultadoReputacion:
        resultado = ResultadoReputacion(servicio="urlscan", tipo="dominio", indicador=dominio)
        clave_cache = f"urlscan:dominio:{dominio}"

        guardado = self.cache.obtener(clave_cache)
        if guardado is not None:
            resultado.encontrado = guardado.get("escaneos_previos", 0) > 0
            resultado.datos, resultado.desde_cache = guardado, True
            return resultado

        codigo, cuerpo, error = peticion_get(
            self.sesion, URL_BUSQUEDA, {"API-Key": self.api_key},
            {"q": f"domain:{dominio}", "size": 1},
        )
        if error:
            resultado.error = error
            return resultado
        if codigo != 200 or cuerpo is None:
            resultado.error = mensaje_http("urlscan.io", codigo)
            return resultado

        escaneos = cuerpo.get("results") or []
        resultado.datos = {"escaneos_previos": cuerpo.get("total", len(escaneos))}
        if escaneos and escaneos[0].get("_id"):
            resultado.datos["ultimo_informe"] = f"https://urlscan.io/result/{escaneos[0]['_id']}/"
        resultado.encontrado = resultado.datos["escaneos_previos"] > 0
        self.cache.guardar(clave_cache, resultado.datos)
        return resultado
