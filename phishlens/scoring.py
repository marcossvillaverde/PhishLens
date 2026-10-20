"""
Módulo de puntuación de riesgo.

Convierte la lista de hallazgos deterministas en una puntuación de 0 a 100
y en un veredicto. Es la parte que "decide": la IA, más adelante, podrá
explicar y matizar, pero nunca rebajar por sí sola un veredicto de riesgo.
"""

from dataclasses import dataclass, field
from enum import Enum

from phishlens.checks.modelos import Hallazgo, Severidad

# Puntos que suma cada hallazgo según su severidad
PESOS = {
    Severidad.INFO: 0,
    Severidad.BAJA: 5,
    Severidad.MEDIA: 15,
    Severidad.ALTA: 25,
    Severidad.CRITICA: 40,
}

# Umbrales de la puntuación para cada veredicto
UMBRAL_SOSPECHOSO = 20
UMBRAL_PHISHING = 50


class Veredicto(str, Enum):
    LIMPIO = "limpio"            # no se han encontrado indicios relevantes
    SOSPECHOSO = "sospechoso"    # hay indicios: requiere revisión
    PHISHING = "phishing"        # indicios claros de ataque


@dataclass
class ResultadoPuntuacion:
    puntuacion: int                      # 0-100
    veredicto: Veredicto
    desglose: dict[str, int] = field(default_factory=dict)   # código -> puntos aportados


def puntuar(hallazgos: list[Hallazgo]) -> ResultadoPuntuacion:
    """
    Calcula la puntuación de riesgo.

    - Cada código de hallazgo cuenta una sola vez (con su severidad más alta),
      para que diez enlaces sin HTTPS no pesen como diez indicios distintos.
    - La suma se limita a 100.
    - Un hallazgo CRÍTICO obliga, como mínimo, a un veredicto SOSPECHOSO.
    - Solo con hallazgos de severidad BAJA el correo nunca pasa de LIMPIO: son
      indicios débiles, frecuentes también en correo legítimo, y la evaluación
      con correos reales mostró que sumados provocaban muchos falsos positivos.
    """
    desglose: dict[str, int] = {}
    for hallazgo in hallazgos:
        puntos = PESOS[hallazgo.severidad]
        desglose[hallazgo.codigo] = max(desglose.get(hallazgo.codigo, 0), puntos)

    puntuacion = min(100, sum(desglose.values()))

    if puntuacion >= UMBRAL_PHISHING:
        veredicto = Veredicto.PHISHING
    elif puntuacion >= UMBRAL_SOSPECHOSO:
        veredicto = Veredicto.SOSPECHOSO
    else:
        veredicto = Veredicto.LIMPIO

    # Indicios débiles: sin ningún hallazgo de severidad MEDIA o superior, el correo es LIMPIO
    relevantes = {Severidad.MEDIA, Severidad.ALTA, Severidad.CRITICA}
    if not any(h.severidad in relevantes for h in hallazgos):
        veredicto = Veredicto.LIMPIO

    # Regla de seguridad: con un hallazgo crítico nunca se da el correo por limpio
    if veredicto == Veredicto.LIMPIO and any(h.severidad == Severidad.CRITICA for h in hallazgos):
        veredicto = Veredicto.SOSPECHOSO

    return ResultadoPuntuacion(puntuacion=puntuacion, veredicto=veredicto, desglose=desglose)
