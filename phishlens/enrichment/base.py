"""
Piezas comunes a todos los servicios de reputación: caché en disco,
control de cuota y resultado de una consulta.
"""

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests

TIMEOUT_HTTP = 10                  # segundos máximos por petición
DURACION_CACHE = 24 * 3600         # las respuestas se reutilizan durante 24 horas
AGENTE = "PhishLens/0.4 (proyecto académico U-tad)"


@dataclass
class ResultadoReputacion:
    """Respuesta normalizada de un servicio de reputación."""
    servicio: str                  # "virustotal", "abuseipdb", "urlscan"
    tipo: str                      # "url", "hash", "dominio", "ip"
    indicador: str                 # el valor consultado
    encontrado: bool = False       # el servicio conoce el indicador
    datos: dict[str, Any] = field(default_factory=dict)   # campos relevantes ya extraídos
    error: str = ""                # mensaje si la consulta falló
    desde_cache: bool = False


class Cache:
    """Caché muy simple en disco: un fichero JSON por consulta."""

    def __init__(self, carpeta: Path, duracion: int = DURACION_CACHE, reloj: Callable[[], float] = time.time):
        self.carpeta = Path(carpeta)
        self.duracion = duracion
        self.reloj = reloj

    def _ruta(self, clave: str) -> Path:
        # El nombre del fichero es un hash: no deja URLs ni IPs legibles en el disco
        return self.carpeta / (hashlib.sha256(clave.encode()).hexdigest() + ".json")

    def obtener(self, clave: str) -> dict | None:
        ruta = self._ruta(clave)
        if not ruta.is_file():
            return None
        try:
            contenido = json.loads(ruta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if self.reloj() - contenido.get("guardado", 0) > self.duracion:
            return None
        return contenido.get("datos")

    def guardar(self, clave: str, datos: dict) -> None:
        try:
            self.carpeta.mkdir(parents=True, exist_ok=True)
            self._ruta(clave).write_text(
                json.dumps({"guardado": self.reloj(), "datos": datos}), encoding="utf-8"
            )
        except OSError:
            pass  # si no se puede escribir la caché, se sigue sin ella


class LimitadorCuota:
    """
    Permite como máximo `maximo` peticiones en cada ventana de `ventana` segundos.
    Si se alcanza el límite, espera lo necesario antes de la siguiente.
    """

    def __init__(self, maximo: int, ventana: float,
                 reloj: Callable[[], float] = time.monotonic,
                 dormir: Callable[[float], None] = time.sleep):
        self.maximo = maximo
        self.ventana = ventana
        self.reloj = reloj
        self.dormir = dormir
        self.marcas: deque[float] = deque()

    def esperar_turno(self) -> None:
        ahora = self.reloj()
        while self.marcas and ahora - self.marcas[0] >= self.ventana:
            self.marcas.popleft()
        if len(self.marcas) >= self.maximo:
            espera = self.ventana - (ahora - self.marcas[0])
            if espera > 0:
                self.dormir(espera)
            self.marcas.popleft()
        self.marcas.append(self.reloj())


def mensaje_http(servicio: str, codigo: int) -> str:
    """Traduce un código HTTP de error a un mensaje comprensible."""
    if codigo in (401, 403):
        return f"{servicio} rechazó la clave de API o denegó el acceso (HTTP {codigo})"
    if codigo == 429:
        return f"cuota de {servicio} agotada"
    if codigo == 422:
        return f"{servicio} no admite este indicador (por ejemplo, una IP reservada o privada)"
    return f"respuesta inesperada de {servicio} (HTTP {codigo})"


def peticion_get(sesion: requests.Session, url: str, cabeceras: dict, parametros: dict | None = None):
    """
    Hace un GET y devuelve (codigo_http, json | None, error).
    Nunca lanza excepciones: un servicio caído no debe romper el análisis.
    """
    try:
        respuesta = sesion.get(url, headers={"User-Agent": AGENTE, **cabeceras},
                               params=parametros, timeout=TIMEOUT_HTTP)
    except requests.RequestException as exc:
        return 0, None, f"sin conexión con el servicio ({type(exc).__name__})"
    try:
        cuerpo = respuesta.json()
    except ValueError:
        cuerpo = None
    return respuesta.status_code, cuerpo, ""
