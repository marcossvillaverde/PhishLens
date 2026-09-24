"""
Validación de la respuesta del modelo.

La respuesta de la IA se trata como un dato no fiable más: si no es un
JSON con el esquema esperado, se descarta. Los valores fuera de las listas
permitidas (tipos de fraude, tácticas, técnicas MITRE) se eliminan, para
que una alucinación o una manipulación no llegue al informe.
"""

import json
import re
from dataclasses import dataclass, field

TIPOS_FRAUDE = {
    "robo_credenciales", "fraude_ceo_bec", "malware", "estafa_pago",
    "extorsion", "spam_comercial", "legitimo", "otro",
}

TACTICAS = {
    "urgencia", "miedo", "autoridad", "suplantacion_marca", "recompensa",
    "curiosidad", "peticion_credenciales", "peticion_pago", "peticion_secreto",
    "manipulacion_ia",
}

# Técnicas de MITRE ATT&CK relacionadas con el phishing
TECNICAS_MITRE = {
    "T1566", "T1566.001", "T1566.002", "T1566.003", "T1566.004",
    "T1598", "T1598.002", "T1598.003",
    "T1204.001", "T1204.002", "T1656", "T1534",
}

# Técnicas que solo tienen sentido si el correo contiene ese tipo de evidencia
REQUIEREN_ADJUNTO_SOSPECHOSO = {"T1566.001", "T1204.002"}
REQUIEREN_ENLACE = {"T1566.002", "T1598.003", "T1204.001"}

MAX_LONGITUD_TEXTO = 1200


@dataclass
class AnalisisIA:
    probabilidad_phishing: float        # 0 = seguro que es legítimo, 1 = seguro que es phishing
    tipo_fraude: str
    tacticas: list[str] = field(default_factory=list)
    tecnicas_mitre: list[str] = field(default_factory=list)
    explicacion: str = ""
    recomendacion: str = ""

    @property
    def es_phishing_probable(self) -> bool:
        return self.probabilidad_phishing >= 0.5


def _extraer_json(texto: str) -> dict | None:
    """Admite la respuesta tal cual o envuelta en ```json ... ```; nada más."""
    limpio = texto.strip()
    limpio = re.sub(r"^```(?:json)?\s*|\s*```$", "", limpio, flags=re.IGNORECASE)
    try:
        datos = json.loads(limpio)
    except (json.JSONDecodeError, TypeError):
        return None
    return datos if isinstance(datos, dict) else None


def _limpiar_texto(valor) -> str:
    """Quita enlaces y recorta: el informe nunca muestra URLs escritas por la IA."""
    texto = str(valor or "").strip()
    texto = re.sub(r"(https?|hxxps?)://\S+", "[enlace omitido]", texto, flags=re.IGNORECASE)
    return texto[:MAX_LONGITUD_TEXTO]


def validar_respuesta(texto: str) -> tuple[AnalisisIA | None, list[str]]:
    """
    Valida la respuesta del modelo.

    Devuelve (análisis, avisos). Si la respuesta no es utilizable, el análisis es None.
    """
    avisos: list[str] = []
    datos = _extraer_json(texto)
    if datos is None:
        return None, ["la respuesta de la IA no es un JSON válido"]

    valor = datos.get("probabilidad_phishing")
    if isinstance(valor, bool):
        return None, ["'probabilidad_phishing' debe ser un número, no un booleano"]
    try:
        probabilidad = float(valor)
    except (TypeError, ValueError):
        return None, ["falta 'probabilidad_phishing' o no es numérica"]
    if not 0 <= probabilidad <= 1:
        avisos.append(f"probabilidad fuera de rango ({probabilidad}); se ajusta")
        probabilidad = min(1.0, max(0.0, probabilidad))

    tipo = str(datos.get("tipo_fraude", "")).strip().lower()
    if tipo not in TIPOS_FRAUDE:
        avisos.append(f"tipo de fraude no permitido ('{tipo}'); se usa 'otro'")
        tipo = "otro"

    def filtrar(clave: str, permitidos: set[str], normalizar) -> list[str]:
        valores = datos.get(clave) or []
        if not isinstance(valores, list):
            avisos.append(f"'{clave}' no es una lista; se ignora")
            return []
        aceptados = []
        for v in valores:
            v = normalizar(str(v))
            if v in permitidos and v not in aceptados:
                aceptados.append(v)
            else:
                avisos.append(f"valor descartado en '{clave}': {v}")
        return aceptados

    tacticas = filtrar("tacticas", TACTICAS, lambda v: v.strip().lower())
    tecnicas = filtrar("tecnicas_mitre", TECNICAS_MITRE, lambda v: v.strip().upper())

    explicacion = _limpiar_texto(datos.get("explicacion"))
    if not explicacion:
        return None, avisos + ["la IA no ha dado ninguna explicación"]

    return AnalisisIA(
        probabilidad_phishing=probabilidad,
        tipo_fraude=tipo,
        tacticas=tacticas,
        tecnicas_mitre=tecnicas,
        explicacion=explicacion,
        recomendacion=_limpiar_texto(datos.get("recomendacion")),
    ), avisos


def ajustar_a_evidencias(analisis: AnalisisIA, adjunto_sospechoso: bool, hay_enlaces: bool) -> list[str]:
    """
    Elimina técnicas MITRE que contradicen las evidencias del correo
    (por ejemplo, "adjunto malicioso" cuando ningún adjunto ha dado indicios de riesgo).
    Devuelve los avisos de lo que se ha quitado.
    """
    avisos = []
    validas = []
    for tecnica in analisis.tecnicas_mitre:
        if tecnica in REQUIEREN_ADJUNTO_SOSPECHOSO and not adjunto_sospechoso:
            avisos.append(f"{tecnica} descartada: ningún adjunto presenta indicios de riesgo")
        elif tecnica in REQUIEREN_ENLACE and not hay_enlaces:
            avisos.append(f"{tecnica} descartada: el correo no tiene enlaces")
        else:
            validas.append(tecnica)
    analisis.tecnicas_mitre = validas
    return avisos
