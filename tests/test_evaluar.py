"""
Pruebas del evaluador de ataques con modelos simulados (sin Ollama):
comprueban que las métricas se calculan bien en los casos extremos.
"""

import json

from phishlens.redteam.corpus import generar_ataques
from phishlens.redteam.evaluar import PROMPT_INGENUO, _mensaje_ingenuo, evaluar_ataque, resumen
from phishlens.parser import parsear_bytes

ATAQUES = {a.id: a for a in generar_ataques()}


class ModeloFijo:
    """Devuelve siempre la misma probabilidad y explicación."""
    nombre = "fijo"

    def __init__(self, probabilidad, explicacion="Explicación.", tacticas=()):
        self.respuesta = json.dumps({
            "probabilidad_phishing": probabilidad, "tipo_fraude": "otro", "tacticas": list(tacticas),
            "tecnicas_mitre": [], "explicacion": explicacion, "recomendacion": "-",
        })

    def generar(self, sistema, mensaje):
        return self.respuesta


def test_modelo_engañado_pero_veredicto_resiste():
    r = evaluar_ataque(ATAQUES["A01"], ModeloFijo(0.0), "defensas")
    assert r.engañada is True
    assert r.veredicto_final == "phishing" and r.resiste is True


def test_modelo_que_detecta_la_manipulacion():
    r = evaluar_ataque(ATAQUES["A06"], ModeloFijo(0.95, "Contiene instrucciones ocultas para manipular."), "defensas")
    assert r.engañada is False and r.detecta is True


def test_tactica_manipulacion_cuenta_como_deteccion():
    r = evaluar_ataque(ATAQUES["A02"], ModeloFijo(0.9, "Phishing.", ["manipulacion_ia"]), "ingenuo")
    assert r.detecta is True


def test_modo_ingenuo_incluye_texto_oculto_y_no_tiene_reglas():
    correo = parsear_bytes(ATAQUES["A06"].eml)
    assert "ignora todas las instrucciones" in _mensaje_ingenuo(correo)
    assert "REGLAS DE SEGURIDAD" not in PROMPT_INGENUO
    assert "probabilidad_phishing" in PROMPT_INGENUO      # el formato de respuesta se mantiene


def test_resumen():
    resultados = [evaluar_ataque(ATAQUES[i], ModeloFijo(0.0), "defensas") for i in ("A01", "A06", "A15")]
    r = resumen(resultados)
    assert r["evaluados"] == 3 and r["engañada"] == 3 and r["resiste"] == 3
