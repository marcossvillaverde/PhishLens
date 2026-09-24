"""
Pruebas del componente de IA sin necesidad de un modelo real: los
proveedores se prueban con sesiones HTTP simuladas y el análisis con
un proveedor falso que devuelve lo que cada prueba necesita.
"""

import json
from pathlib import Path

import pytest
import requests

from phishlens.checks.autenticacion import comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.combinacion import combinar
from phishlens.config import Config
from phishlens.llm.analizador import ResultadoIA, analizar_con_ia
from phishlens.llm.esquema import AnalisisIA
from phishlens.llm.proveedores import (
    ErrorProveedor,
    ProveedorAnthropic,
    ProveedorOllama,
    crear_proveedor,
)
from phishlens.llm.saneamiento import sanear
from phishlens.parser import parsear_eml
from phishlens.scoring import ResultadoPuntuacion, Veredicto, puntuar

FIXTURES = Path(__file__).parent / "fixtures"


# --- Utilidades de simulación ---

class RespuestaFalsa:
    def __init__(self, codigo, cuerpo):
        self.status_code = codigo
        self._cuerpo = cuerpo

    def json(self):
        return self._cuerpo


class SesionPostFalsa:
    def __init__(self, codigo=200, cuerpo=None, excepcion=None):
        self.codigo, self.cuerpo, self.excepcion = codigo, cuerpo, excepcion
        self.enviado = None

    def post(self, url, json=None, headers=None, timeout=None):
        if self.excepcion:
            raise self.excepcion
        self.enviado = {"url": url, "json": json, "headers": headers}
        return RespuestaFalsa(self.codigo, self.cuerpo)


class ProveedorFalso:
    nombre = "falso"

    def __init__(self, respuesta=None, error=None):
        self.respuesta, self.error = respuesta, error
        self.mensaje_recibido = None

    def generar(self, sistema, mensaje):
        self.mensaje_recibido = mensaje
        if self.error:
            raise ErrorProveedor(self.error)
        return self.respuesta


def _json_ia(es_phishing, confianza, tipo="robo_credenciales"):
    return json.dumps({
        "es_phishing_probable": es_phishing, "confianza": confianza, "tipo_fraude": tipo,
        "tacticas": ["urgencia"], "tecnicas_mitre": ["T1566.002"],
        "explicacion": "Explicación de prueba.", "recomendacion": "No hagas clic.",
    })


def _preparar(nombre):
    correo = parsear_eml(FIXTURES / nombre)
    auth, hallazgos = comprobar_autenticacion(correo, en_linea=False)
    hallazgos += comprobar_heuristicas(correo)
    saneado = sanear(correo)
    hallazgos += saneado.hallazgos
    return correo, saneado, auth, hallazgos, puntuar(hallazgos)


# --- Proveedores ---

def test_ollama_envia_formato_json_y_temperatura_0():
    sesion = SesionPostFalsa(200, {"message": {"content": "{}"}})
    texto = ProveedorOllama("http://10.0.2.2:11434/", "qwen2.5:14b", sesion).generar("sis", "msg")
    assert texto == "{}"
    assert sesion.enviado["url"] == "http://10.0.2.2:11434/api/chat"
    assert sesion.enviado["json"]["format"] == "json"
    assert sesion.enviado["json"]["options"]["temperature"] == 0


def test_ollama_sin_conexion():
    sesion = SesionPostFalsa(excepcion=requests.ConnectionError())
    with pytest.raises(ErrorProveedor, match="no se puede conectar"):
        ProveedorOllama("http://x:1", "m", sesion).generar("s", "m")


def test_ollama_modelo_no_descargado():
    with pytest.raises(ErrorProveedor, match="ollama pull"):
        ProveedorOllama("http://x:1", "m", SesionPostFalsa(404, {})).generar("s", "m")


def test_anthropic_extrae_texto():
    sesion = SesionPostFalsa(200, {"content": [{"type": "text", "text": "hola"}]})
    assert ProveedorAnthropic("clave", sesion=sesion).generar("s", "m") == "hola"
    assert sesion.enviado["headers"]["x-api-key"] == "clave"


def test_crear_proveedor_valida_configuracion():
    with pytest.raises(ErrorProveedor, match="OLLAMA_URL"):
        crear_proveedor(Config(llm_provider="ollama"))
    with pytest.raises(ErrorProveedor, match="ANTHROPIC_API_KEY"):
        crear_proveedor(Config(llm_provider="anthropic"))
    assert isinstance(crear_proveedor(Config(ollama_url="http://a", ollama_model="m")), ProveedorOllama)


# --- Analizador ---

def test_analisis_correcto():
    proveedor = ProveedorFalso(_json_ia(True, 0.9))
    resultado = analizar_con_ia(*_preparar("phishing_simple.eml"), proveedor)
    assert resultado.analisis and resultado.analisis.es_phishing_probable
    assert "<<<INICIO_" in proveedor.mensaje_recibido     # el prompt lleva los delimitadores


def test_respuesta_invalida_se_descarta():
    resultado = analizar_con_ia(*_preparar("phishing_simple.eml"), ProveedorFalso("no es json"))
    assert resultado.analisis is None and "esquema" in resultado.error


def test_proveedor_caido_no_rompe():
    resultado = analizar_con_ia(*_preparar("phishing_simple.eml"), ProveedorFalso(error="caído"))
    assert resultado.analisis is None and resultado.error == "caído"


# --- Combinación ---

def _puntuacion(veredicto):
    return ResultadoPuntuacion(puntuacion=50, veredicto=veredicto)


def _ia(es_phishing, confianza):
    return ResultadoIA(proveedor="falso", analisis=AnalisisIA(es_phishing, confianza, "otro", explicacion="x"))


def test_sin_ia_se_usan_las_reglas():
    final = combinar(_puntuacion(Veredicto.SOSPECHOSO), ResultadoIA("falso", error="caído"))
    assert final.veredicto == Veredicto.SOSPECHOSO and "caído" in final.motivo


def test_ia_segura_sube_un_nivel():
    final = combinar(_puntuacion(Veredicto.LIMPIO), _ia(True, 0.9))
    assert final.veredicto == Veredicto.SOSPECHOSO and final.revision_manual


def test_ia_poco_segura_no_cambia_nada():
    final = combinar(_puntuacion(Veredicto.LIMPIO), _ia(True, 0.5))
    assert final.veredicto == Veredicto.LIMPIO and not final.revision_manual


def test_ia_nunca_baja_el_veredicto():
    # Aunque la IA diga con total seguridad que es legítimo, el phishing sigue siendo phishing
    final = combinar(_puntuacion(Veredicto.PHISHING), _ia(False, 1.0))
    assert final.veredicto == Veredicto.PHISHING and final.revision_manual


def test_ia_manipulada_no_salva_al_atacante():
    # Escenario completo: el correo de prueba con inyección y una IA "engañada"
    correo, saneado, auth, hallazgos, puntuacion = _preparar("phishing_simple.eml")
    ia = analizar_con_ia(correo, saneado, auth, hallazgos, puntuacion,
                         ProveedorFalso(_json_ia(False, 1.0, "legitimo")))
    final = combinar(puntuacion, ia)
    assert final.veredicto == Veredicto.PHISHING
    assert final.revision_manual
