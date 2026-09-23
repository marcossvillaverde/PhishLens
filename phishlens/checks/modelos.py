"""
Modelos de datos comunes a todas las comprobaciones.

Cada comprobación devuelve una lista de Hallazgo. Más adelante, el módulo
de puntuación sumará el riesgo de cada hallazgo según su severidad.
"""

from dataclasses import dataclass
from enum import Enum

import tldextract

# Extractor de dominios que usa la lista de sufijos incluida en la librería,
# sin descargarla de internet (la herramienta no hace conexiones innecesarias)
_extractor = tldextract.TLDExtract(suffix_list_urls=())


class Severidad(str, Enum):
    """Nivel de gravedad de un hallazgo."""
    INFO = "info"        # dato informativo, no suma riesgo
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"


@dataclass
class Hallazgo:
    """Un indicio detectado en el correo."""
    codigo: str           # identificador único, p. ej. "SPF_FAIL"
    categoria: str        # "autenticacion", "remitente", "urls", "adjuntos"...
    severidad: Severidad
    descripcion: str      # explicación en español para el informe
    evidencia: str = ""   # dato concreto que lo demuestra


def dominio_de_correo(direccion: str) -> str:
    """Devuelve el dominio de una dirección de correo en minúsculas."""
    return direccion.rsplit("@", 1)[-1].strip().lower() if "@" in direccion else ""


def dominio_organizativo(dominio: str) -> str:
    """
    Devuelve el dominio "registrable" (organizativo).

    Ejemplo: mail.secure.paypal.com -> paypal.com ; web.bbva.co.uk -> bbva.co.uk
    """
    if not dominio:
        return ""
    resultado = _extractor(dominio.lower())
    if resultado.domain and resultado.suffix:
        return f"{resultado.domain}.{resultado.suffix}"
    return dominio.lower()
