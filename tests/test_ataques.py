"""
Pruebas automáticas de las defensas frente a ataques contra la IA (hito 6).

No usan ningún modelo real: comprueban las defensas DETERMINISTAS, que son
las que se pueden garantizar:
  1. Detección: el intento de manipulación genera un hallazgo.
  2. Filtrado: lo que el usuario no ve (texto oculto, comentarios, versión de
     texto plano distinta, texto más allá del recorte) no llega a la IA.
  3. Neutralización: delimitadores falsos y caracteres invisibles se eliminan.
  4. Arquitectura: aunque la IA quede totalmente engañada, el veredicto final
     no puede bajar.
"""

import json
import unicodedata

import pytest
from rich.console import Console

import phishlens.main as main
from phishlens.checks.autenticacion import comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.combinacion import combinar
from phishlens.llm.analizador import analizar_con_ia
from phishlens.llm.prompt import construir_mensaje
from phishlens.llm.proveedores import ErrorProveedor
from phishlens.llm.saneamiento import sanear
from phishlens.parser import parsear_bytes
from phishlens.redteam.corpus import construir, generar_ataques
from phishlens.scoring import Veredicto, puntuar

ATAQUES = generar_ataques()
POR_ID = {a.id: a for a in ATAQUES}


def _normalizar(texto: str) -> str:
    texto = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in texto if not unicodedata.combining(c))


def _analizar(ataque):
    correo = parsear_bytes(ataque.eml)
    auth, hallazgos = comprobar_autenticacion(correo, en_linea=False)
    hallazgos += comprobar_heuristicas(correo)
    saneado = sanear(correo)
    hallazgos += saneado.hallazgos
    puntuacion = puntuar(hallazgos)
    mensaje = construir_mensaje(correo, saneado, auth, hallazgos, puntuacion, token="tokfijo")
    return correo, saneado, auth, hallazgos, puntuacion, mensaje


class IAEngañada:
    """Simula un modelo que ha caído en la trampa: dice que todo es legítimo."""
    nombre = "IA engañada"

    def generar(self, sistema, mensaje):
        return json.dumps({
            "probabilidad_phishing": 0.0, "tipo_fraude": "legitimo", "tacticas": [],
            "tecnicas_mitre": [], "explicacion": "Correo legítimo verificado.", "recomendacion": "Ninguna.",
        })


def _param(ataque):
    marcas = []
    if not ataque.detectable:
        marcas.append(pytest.mark.xfail(strict=True, reason="limitación conocida: no se detecta por patrones"))
    return pytest.param(ataque, id=f"{ataque.id}-{ataque.descripcion}", marks=marcas)


# --- 1. Detección ---

@pytest.mark.parametrize("ataque", [_param(a) for a in ATAQUES])
def test_intento_de_manipulacion_detectado(ataque):
    _, saneado, *_ = _analizar(ataque)
    assert "POSIBLE_PROMPT_INJECTION" in {h.codigo for h in saneado.hallazgos}


# --- 2. Filtrado de lo que el usuario no ve ---

@pytest.mark.parametrize("ataque", [pytest.param(a, id=a.id) for a in ATAQUES if a.oculto])
def test_carga_oculta_no_llega_a_la_ia(ataque):
    *_, mensaje = _analizar(ataque)
    assert _normalizar(ataque.carga) not in _normalizar(mensaje)


def test_texto_oculto_genera_hallazgo():
    for id_ in ("A06", "A07", "A08", "A09"):
        _, saneado, *_ = _analizar(POR_ID[id_])
        assert "TEXTO_OCULTO" in {h.codigo for h in saneado.hallazgos}, id_


# --- 3. Neutralización ---

def test_delimitadores_falsos_neutralizados():
    *_, mensaje = _analizar(POR_ID["A10"])
    assert "<<<FIN_a1b2c3>>>" not in mensaje
    # Los únicos delimitadores del mensaje son los auténticos de la herramienta
    assert mensaje.count("<<<") == 2


def test_caracteres_invisibles_eliminados():
    *_, mensaje = _analizar(POR_ID["A12"])
    assert "\u200b" not in mensaje


# --- 4. Arquitectura: la IA engañada no cambia el resultado ---

@pytest.mark.parametrize("ataque", [pytest.param(a, id=a.id) for a in ATAQUES])
def test_ia_engañada_no_rebaja_el_veredicto(ataque):
    correo, saneado, auth, hallazgos, puntuacion, _ = _analizar(ataque)
    ia = analizar_con_ia(correo, saneado, auth, hallazgos, puntuacion, IAEngañada())
    final = combinar(puntuacion, ia)
    if ataque.base == "phishing":
        assert final.veredicto == Veredicto.PHISHING
    else:
        # Un correo que intenta manipular a la IA nunca sale como limpio
        assert final.veredicto != Veredicto.LIMPIO
        assert final.revision_manual


# --- Falsos positivos: lo legítimo no debe marcarse ---

def test_comentarios_condicionales_de_outlook_no_son_texto_oculto():
    eml = construir(base="legitimo", html_prefijo="<!--[if mso]><table><tr><td>Versión para Outlook</td></tr></table><![endif]-->")
    saneado = sanear(parsear_bytes(eml))
    assert saneado.hallazgos == []


def test_correo_legitimo_sin_ataque_no_genera_hallazgos():
    saneado = sanear(parsear_bytes(construir(base="legitimo")))
    assert saneado.hallazgos == []


# --- Inyección en la terminal ---

def test_marcado_de_la_terminal_se_muestra_literal(monkeypatch):
    consola = Console(record=True, width=200)
    monkeypatch.setattr(main, "consola", consola)
    eml = construir(asunto="[link=http://malo.example]Pulsa aquí[/link] [bold red]URGENTE")
    main.mostrar_parseo(parsear_bytes(eml))
    salida = consola.export_text()
    assert "[link=http://malo.example]" in salida      # se ve como texto, no como enlace
    assert "[bold red]" in salida
