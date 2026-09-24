"""
Proveedores de modelos de lenguaje.

  - ProveedorOllama: modelo local ejecutado con Ollama en el equipo anfitrión.
    Es el proveedor por defecto: el correo no sale del equipo.
  - ProveedorAnthropic: API de Anthropic (Claude), como alternativa y para comparar.

Los dos exponen el mismo método generar(sistema, mensaje) -> texto, así que el
resto de la herramienta no necesita saber cuál se está usando.
Ninguno de los dos da herramientas al modelo: solo recibe texto y devuelve texto.
"""

import requests

from phishlens.config import Config

TIMEOUT_OLLAMA = 180        # la primera petición incluye cargar el modelo en la GPU
TIMEOUT_API = 60
MODELO_ANTHROPIC = "claude-haiku-4-5-20251001"
URL_ANTHROPIC = "https://api.anthropic.com/v1/messages"


class ErrorProveedor(Exception):
    """Fallo al comunicarse con el modelo (red, configuración, modelo no disponible...)."""


class ProveedorOllama:
    def __init__(self, url: str, modelo: str, sesion: requests.Session | None = None,
                 timeout: int = TIMEOUT_OLLAMA):
        self.url = url.rstrip("/")
        self.modelo = modelo
        self.sesion = sesion or requests.Session()
        self.timeout = timeout

    @property
    def nombre(self) -> str:
        return f"Ollama local ({self.modelo})"

    def generar(self, sistema: str, mensaje: str) -> str:
        cuerpo = {
            "model": self.modelo,
            "messages": [
                {"role": "system", "content": sistema},
                {"role": "user", "content": mensaje},
            ],
            "stream": False,
            "format": "json",                                  # obliga al modelo a devolver JSON
            "options": {"temperature": 0, "num_ctx": 4096},   # respuestas estables y memoria acotada
        }
        try:
            respuesta = self.sesion.post(f"{self.url}/api/chat", json=cuerpo, timeout=self.timeout)
        except requests.Timeout:
            raise ErrorProveedor(f"Ollama no respondió en {self.timeout} s")
        except requests.RequestException:
            raise ErrorProveedor(f"no se puede conectar con Ollama en {self.url} (¿está abierto en Windows?)")

        if respuesta.status_code == 404:
            raise ErrorProveedor(f"Ollama no tiene el modelo '{self.modelo}' (ejecuta 'ollama pull {self.modelo}')")
        if respuesta.status_code != 200:
            raise ErrorProveedor(f"Ollama devolvió HTTP {respuesta.status_code}")
        try:
            return respuesta.json()["message"]["content"]
        except (ValueError, KeyError, TypeError):
            raise ErrorProveedor("respuesta de Ollama con formato inesperado")


class ProveedorAnthropic:
    def __init__(self, api_key: str, modelo: str = MODELO_ANTHROPIC,
                 sesion: requests.Session | None = None, timeout: int = TIMEOUT_API):
        self.api_key = api_key
        self.modelo = modelo
        self.sesion = sesion or requests.Session()
        self.timeout = timeout

    @property
    def nombre(self) -> str:
        return f"API de Anthropic ({self.modelo})"

    def generar(self, sistema: str, mensaje: str) -> str:
        cabeceras = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        cuerpo = {
            "model": self.modelo,
            "max_tokens": 800,
            "temperature": 0,
            "system": sistema,
            "messages": [{"role": "user", "content": mensaje}],
        }
        try:
            respuesta = self.sesion.post(URL_ANTHROPIC, headers=cabeceras, json=cuerpo, timeout=self.timeout)
        except requests.RequestException:
            raise ErrorProveedor("no se puede conectar con la API de Anthropic")

        if respuesta.status_code in (401, 403):
            raise ErrorProveedor("la API de Anthropic rechazó la clave")
        if respuesta.status_code != 200:
            raise ErrorProveedor(f"la API de Anthropic devolvió HTTP {respuesta.status_code}")
        try:
            bloques = respuesta.json()["content"]
            return "".join(b.get("text", "") for b in bloques if b.get("type") == "text")
        except (ValueError, KeyError, TypeError):
            raise ErrorProveedor("respuesta de la API de Anthropic con formato inesperado")


def crear_proveedor(config: Config):
    """Crea el proveedor indicado en LLM_PROVIDER, comprobando que está configurado."""
    if config.llm_provider == "ollama":
        if not config.ollama_url or not config.ollama_model:
            raise ErrorProveedor("faltan OLLAMA_URL u OLLAMA_MODEL en el .env")
        return ProveedorOllama(config.ollama_url, config.ollama_model)
    if config.llm_provider == "anthropic":
        if not config.anthropic_api_key:
            raise ErrorProveedor("falta ANTHROPIC_API_KEY en el .env")
        return ProveedorAnthropic(config.anthropic_api_key)
    raise ErrorProveedor(f"LLM_PROVIDER desconocido: '{config.llm_provider}' (usa 'ollama' o 'anthropic')")
