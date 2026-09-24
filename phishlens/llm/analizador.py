"""
Punto de entrada del componente de IA: construye el prompt, llama al
proveedor y valida la respuesta.

Si algo falla (proveedor caído, respuesta inválida), devuelve el error en
lugar de lanzar una excepción: la herramienta sigue funcionando solo con
las reglas deterministas.
"""

import time
from dataclasses import dataclass, field

from phishlens.checks.autenticacion import ResultadoAutenticacion
from phishlens.checks.modelos import Hallazgo
from phishlens.llm.esquema import AnalisisIA, validar_respuesta
from phishlens.llm.prompt import PROMPT_SISTEMA, construir_mensaje
from phishlens.llm.proveedores import ErrorProveedor
from phishlens.llm.saneamiento import ContenidoSaneado
from phishlens.parser import CorreoParseado
from phishlens.scoring import ResultadoPuntuacion


@dataclass
class ResultadoIA:
    proveedor: str
    analisis: AnalisisIA | None = None
    avisos: list[str] = field(default_factory=list)   # valores descartados, ajustes...
    error: str = ""
    segundos: float = 0.0


def analizar_con_ia(correo: CorreoParseado, saneado: ContenidoSaneado, auth: ResultadoAutenticacion,
                    hallazgos: list[Hallazgo], puntuacion: ResultadoPuntuacion, proveedor) -> ResultadoIA:
    resultado = ResultadoIA(proveedor=proveedor.nombre)
    mensaje = construir_mensaje(correo, saneado, auth, hallazgos, puntuacion)

    inicio = time.monotonic()
    try:
        respuesta = proveedor.generar(PROMPT_SISTEMA, mensaje)
    except ErrorProveedor as exc:
        resultado.error = str(exc)
        return resultado
    finally:
        resultado.segundos = round(time.monotonic() - inicio, 1)

    resultado.analisis, resultado.avisos = validar_respuesta(respuesta)
    if resultado.analisis is None:
        resultado.error = "la respuesta de la IA no cumple el esquema y se ha descartado"
    return resultado
