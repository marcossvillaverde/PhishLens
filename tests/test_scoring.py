"""Pruebas del módulo de puntuación."""

from pathlib import Path

from phishlens.checks.autenticacion import comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_heuristicas
from phishlens.checks.modelos import Hallazgo, Severidad
from phishlens.parser import parsear_eml
from phishlens.scoring import Veredicto, puntuar

FIXTURES = Path(__file__).parent / "fixtures"


def _hallazgos_sin_red(nombre_fichero):
    correo = parsear_eml(FIXTURES / nombre_fichero)
    _, hallazgos_auth = comprobar_autenticacion(correo, en_linea=False)
    return hallazgos_auth + comprobar_heuristicas(correo)


def test_correo_phishing_se_clasifica_como_phishing():
    resultado = puntuar(_hallazgos_sin_red("phishing_simple.eml"))
    assert resultado.veredicto == Veredicto.PHISHING
    assert resultado.puntuacion == 100


def test_correo_legitimo_se_clasifica_como_limpio():
    hallazgos = _hallazgos_sin_red("legitimo_simple.eml")
    resultado = puntuar(hallazgos)
    assert hallazgos == []
    assert resultado.veredicto == Veredicto.LIMPIO
    assert resultado.puntuacion == 0


def test_codigo_repetido_cuenta_una_vez():
    hallazgos = [Hallazgo("URL_SIN_HTTPS", "urls", Severidad.BAJA, "x")] * 10
    assert puntuar(hallazgos).puntuacion == 5


def test_hallazgo_critico_nunca_es_limpio():
    # 40 puntos no llegan a PHISHING, pero sí superan SOSPECHOSO
    resultado = puntuar([Hallazgo("URL_TEXTO_ENGANOSO", "urls", Severidad.CRITICA, "x")])
    assert resultado.veredicto == Veredicto.SOSPECHOSO


def test_puntuacion_maxima_100():
    hallazgos = [Hallazgo(f"C{i}", "x", Severidad.CRITICA, "x") for i in range(5)]
    assert puntuar(hallazgos).puntuacion == 100
