"""
Combinación del veredicto de las reglas con el análisis de la IA.

Principio de diseño: EL MOTOR DETERMINISTA DECIDE Y LA IA INTERPRETA.
  - La IA puede SUBIR el veredicto como mucho un nivel (limpio -> sospechoso,
    sospechoso -> phishing), y solo si está segura (confianza >= 0.7).
  - La IA NUNCA puede bajar el veredicto. Si no está de acuerdo con unas
    reglas que ven riesgo, se mantiene el veredicto y se pide revisión manual.
Así, aunque un atacante consiguiera manipular al modelo, no podría hacer
pasar un correo de phishing por uno limpio.
"""

from dataclasses import dataclass

from phishlens.llm.analizador import ResultadoIA
from phishlens.scoring import ResultadoPuntuacion, Veredicto

UMBRAL_CONFIANZA = 0.7
ORDEN = [Veredicto.LIMPIO, Veredicto.SOSPECHOSO, Veredicto.PHISHING]


@dataclass
class VeredictoFinal:
    veredicto: Veredicto
    veredicto_reglas: Veredicto
    puntuacion_reglas: int
    revision_manual: bool
    motivo: str


def combinar(puntuacion: ResultadoPuntuacion, ia: ResultadoIA | None) -> VeredictoFinal:
    reglas = puntuacion.veredicto
    base = dict(veredicto_reglas=reglas, puntuacion_reglas=puntuacion.puntuacion)

    if ia is None or ia.analisis is None:
        motivo = "Veredicto basado solo en las reglas"
        motivo += f" (IA no disponible: {ia.error})." if ia and ia.error else "."
        return VeredictoFinal(reglas, revision_manual=False, motivo=motivo, **base)

    analisis = ia.analisis
    segura = analisis.confianza >= UMBRAL_CONFIANZA

    # La IA ve phishing con seguridad: puede subir un nivel
    if analisis.es_phishing_probable and segura:
        if reglas == Veredicto.PHISHING:
            return VeredictoFinal(reglas, revision_manual=False,
                                  motivo="Las reglas y la IA coinciden: es phishing.", **base)
        nuevo = ORDEN[ORDEN.index(reglas) + 1]
        return VeredictoFinal(nuevo, revision_manual=True,
                              motivo=f"La IA detecta ingeniería social que las reglas no ven; se sube de "
                                     f"{reglas.value} a {nuevo.value} y se recomienda revisión manual.", **base)

    # La IA no ve phishing pero las reglas sí ven riesgo: prevalecen las reglas
    if not analisis.es_phishing_probable and reglas != Veredicto.LIMPIO:
        return VeredictoFinal(reglas, revision_manual=True,
                              motivo="La IA no lo considera phishing, pero las reglas sí detectan riesgo; "
                                     "prevalece el veredicto de las reglas. Revisión manual recomendada.", **base)

    # Resto de casos: coinciden, o la IA sospecha con poca confianza
    if analisis.es_phishing_probable:
        motivo = "La IA sospecha, pero con poca confianza; se mantiene el veredicto de las reglas."
    else:
        motivo = "Las reglas y la IA coinciden."
    return VeredictoFinal(reglas, revision_manual=False, motivo=motivo, **base)
