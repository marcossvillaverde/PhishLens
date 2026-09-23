"""Pruebas de las comprobaciones deterministas (sin conexión de red)."""

from pathlib import Path

import pytest

from phishlens.checks.autenticacion import comprobar_autenticacion, leer_authentication_results
from phishlens.checks.heuristicas import (
    comprobar_adjuntos,
    comprobar_heuristicas,
    detectar_suplantacion_dominio,
)
from phishlens.checks.modelos import Severidad, dominio_organizativo
from phishlens.parser import Adjunto, CorreoParseado, parsear_eml

FIXTURE = Path(__file__).parent / "fixtures" / "phishing_simple.eml"


def _codigos(hallazgos):
    return {h.codigo for h in hallazgos}


# --- Utilidades de dominio ---

@pytest.mark.parametrize("dominio, esperado", [
    ("mail.secure.paypal.com", "paypal.com"),
    ("web.bbva.co.uk", "bbva.co.uk"),
    ("paypal.com", "paypal.com"),
])
def test_dominio_organizativo(dominio, esperado):
    assert dominio_organizativo(dominio) == esperado


# --- Suplantación de dominios ---

@pytest.mark.parametrize("dominio, marca", [
    ("paypa1-verify.com", "paypal"),
    ("micros0ft-soporte.com", "microsoft"),
    ("secure-bbva.net", "bbva"),
    ("amaz0n.shop", "amazon"),
    ("gooogle.com", "google"),
])
def test_detecta_dominios_que_imitan_marcas(dominio, marca):
    assert detectar_suplantacion_dominio(dominio) == marca


@pytest.mark.parametrize("dominio", [
    "paypal.com", "www.paypal.com", "amazon.es", "u-tad.com",
    "correosexpress.com", "applebees.com",
])
def test_no_marca_dominios_legitimos(dominio):
    assert detectar_suplantacion_dominio(dominio) is None


# --- Autenticación (leyendo la cabecera, sin red) ---

def test_lee_authentication_results():
    cabecera = "mx.x; spf=softfail smtp.mailfrom=a.com; dkim=pass header.d=a.com; dmarc=none"
    assert leer_authentication_results(cabecera) == {"spf": "softfail", "dkim": "pass", "dmarc": "none"}


def test_autenticacion_sin_red():
    correo = parsear_eml(FIXTURE)
    resultado, hallazgos = comprobar_autenticacion(correo, en_linea=False)
    assert resultado.fuente == "cabecera"
    assert (resultado.spf, resultado.dkim, resultado.dmarc) == ("fail", "none", "fail")
    assert {"SPF_FAIL", "DKIM_AUSENTE", "DMARC_FAIL"} <= _codigos(hallazgos)


# --- Heurísticas sobre el correo de prueba ---

def test_heuristicas_correo_de_prueba():
    hallazgos = comprobar_heuristicas(parsear_eml(FIXTURE))
    codigos = _codigos(hallazgos)
    assert "REPLY_TO_DISTINTO" in codigos
    assert "URL_TEXTO_ENGANOSO" in codigos
    assert "URL_DOMINIO_SIMILAR" in codigos
    # Reply-To a Gmail cuando el remitente dice ser PayPal: severidad alta
    reply = next(h for h in hallazgos if h.codigo == "REPLY_TO_DISTINTO")
    assert reply.severidad == Severidad.ALTA


def test_adjunto_con_doble_extension():
    correo = CorreoParseado(adjuntos=[Adjunto("factura.pdf.exe", "application/octet-stream", 10, "x", "y")])
    codigos = _codigos(comprobar_adjuntos(correo))
    assert {"ADJUNTO_PELIGROSO", "ADJUNTO_DOBLE_EXTENSION"} <= codigos


def test_adjunto_inofensivo():
    correo = CorreoParseado(adjuntos=[Adjunto("informe.pdf", "application/pdf", 10, "x", "y")])
    assert comprobar_adjuntos(correo) == []
