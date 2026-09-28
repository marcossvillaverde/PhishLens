"""
Orquestación del análisis completo de un correo.

Reúne en un único objeto todo lo que produce la herramienta, para que lo
puedan usar tanto la salida por terminal (main.py) como los informes
(report.py) sin repetir la lógica.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from phishlens.checks.autenticacion import ResultadoAutenticacion, comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.checks.modelos import Hallazgo
from phishlens.combinacion import VeredictoFinal, combinar
from phishlens.config import Config
from phishlens.enrichment.base import ResultadoReputacion
from phishlens.enrichment.enriquecer import enriquecer
from phishlens.llm.analizador import ResultadoIA, analizar_con_ia
from phishlens.llm.proveedores import ErrorProveedor, crear_proveedor
from phishlens.llm.saneamiento import ContenidoSaneado, sanear
from phishlens.parser import CorreoParseado, parsear_bytes
from phishlens.scoring import ResultadoPuntuacion, puntuar

VERSION = "0.7"


@dataclass
class OpcionesAnalisis:
    en_linea: bool = True        # consultas DNS para SPF/DKIM/DMARC
    reputacion: bool = True      # VirusTotal, AbuseIPDB, urlscan.io
    ia: bool = True              # modelo de lenguaje


@dataclass
class ResultadoAnalisis:
    fichero: str
    sha256_fichero: str
    fecha: datetime
    opciones: OpcionesAnalisis
    correo: CorreoParseado
    autenticacion: ResultadoAutenticacion
    saneado: ContenidoSaneado
    hallazgos: list[Hallazgo]
    puntuacion: ResultadoPuntuacion
    final: VeredictoFinal
    reputacion: list[ResultadoReputacion] = field(default_factory=list)
    ia: ResultadoIA | None = None


def analizar(ruta: str | Path, config: Config, opciones: OpcionesAnalisis | None = None,
             avisar: Callable[[str], None] = lambda mensaje: None) -> ResultadoAnalisis:
    """
    Ejecuta el análisis completo. `avisar` recibe mensajes de progreso
    (la terminal los muestra; los tests los ignoran).
    """
    opciones = opciones or OpcionesAnalisis()
    datos = Path(ruta).read_bytes()
    correo = parsear_bytes(datos)

    # 1. Comprobaciones deterministas
    auth, hallazgos = comprobar_autenticacion(correo, en_linea=opciones.en_linea)
    hallazgos += comprobar_heuristicas(correo)

    # 2. Reputación (requiere red)
    reputacion: list[ResultadoReputacion] = []
    if opciones.reputacion and opciones.en_linea:
        avisar("Consultando servicios de reputación...")
        reputacion, hallazgos_rep = enriquecer(correo, config)
        hallazgos += hallazgos_rep

    # 3. Saneamiento (siempre: detecta texto oculto y prompt injection)
    saneado = sanear(correo)
    hallazgos += saneado.hallazgos

    # 4. Puntuación determinista
    puntuacion = puntuar(hallazgos)

    # 5. IA
    resultado_ia = None
    if opciones.ia:
        try:
            proveedor = crear_proveedor(config)
            if not opciones.en_linea and config.llm_provider != "ollama":
                raise ErrorProveedor("sin red no se puede usar una API externa")
            avisar(f"Analizando con {proveedor.nombre}...")
            resultado_ia = analizar_con_ia(correo, saneado, auth, hallazgos, puntuacion, proveedor)
        except ErrorProveedor as exc:
            resultado_ia = ResultadoIA(proveedor=config.llm_provider, error=str(exc))

    # 6. Veredicto final
    return ResultadoAnalisis(
        fichero=Path(ruta).name,
        sha256_fichero=hashlib.sha256(datos).hexdigest(),
        fecha=datetime.now().astimezone(),
        opciones=opciones,
        correo=correo,
        autenticacion=auth,
        saneado=saneado,
        hallazgos=hallazgos,
        puntuacion=puntuacion,
        final=combinar(puntuacion, resultado_ia),
        reputacion=reputacion,
        ia=resultado_ia,
    )
