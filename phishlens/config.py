"""
Configuración de PhishLens.

Lee las claves y opciones del fichero .env de la raíz del proyecto.
Las claves nunca se escriben en el código ni se muestran por pantalla.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

RAIZ_PROYECTO = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    abuseipdb_api_key: str = ""
    llm_provider: str = "ollama"
    ollama_url: str = ""
    ollama_model: str = ""
    anthropic_api_key: str = ""
    carpeta_cache: Path = RAIZ_PROYECTO / ".cache"


def cargar_config() -> Config:
    """Carga el .env (si existe) y devuelve la configuración."""
    load_dotenv(RAIZ_PROYECTO / ".env")
    return Config(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY", "").strip(),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        llm_provider=os.getenv("LLM_PROVIDER", "ollama").strip().lower(),
        ollama_url=os.getenv("OLLAMA_URL", "").strip(),
        ollama_model=os.getenv("OLLAMA_MODEL", "").strip(),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
    )
