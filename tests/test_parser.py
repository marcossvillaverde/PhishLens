"""Pruebas del módulo de parseo usando un correo de phishing ficticio."""

from pathlib import Path

from phishlens.parser import parsear_bytes, parsear_eml

FIXTURE = Path(__file__).parent / "fixtures" / "phishing_simple.eml"


def test_cabeceras_principales():
    correo = parsear_eml(FIXTURE)
    assert correo.remitente == "servicio@paypal.com"
    assert correo.remitente_nombre == "PayPal Seguridad"
    assert correo.reply_to == "soporte.paypal.cuentas@gmail.com"
    assert correo.return_path == "bounce@mailer-ofertas.xyz"
    # El asunto viene codificado (=?UTF-8?Q?...?=) y debe decodificarse
    assert correo.asunto == "Acción requerida: su cuenta será suspendida"
    assert correo.destinatarios == ["victima@ejemplo-destino.es"]


def test_ip_origen_ignora_redes_internas():
    correo = parsear_eml(FIXTURE)
    assert len(correo.received) == 2
    # 192.168.1.10 es interna; el origen real es 203.0.113.50
    assert correo.ip_origen == "203.0.113.50"


def test_url_con_texto_enganoso():
    correo = parsear_eml(FIXTURE)
    # Solo hay un destino real, aunque el texto visible parezca otra URL
    assert len(correo.urls) == 1
    url = correo.urls[0]
    assert url.url == "http://secure-login.paypa1-verify.com/acceso"
    assert url.texto_visible == "https://www.paypal.com/es/signin"
    assert url.origen == "html"


def test_adjunto_con_hashes():
    correo = parsear_eml(FIXTURE)
    assert len(correo.adjuntos) == 1
    adjunto = correo.adjuntos[0]
    assert adjunto.nombre == "factura_2026.txt"
    assert len(adjunto.md5) == 32
    assert len(adjunto.sha256) == 64


def test_correo_minimo_sin_fallos():
    # Un correo casi vacío no debe romper el parser
    correo = parsear_bytes(b"From: a@b.com\r\nSubject: hola\r\n\r\ncuerpo")
    assert correo.remitente == "a@b.com"
    assert correo.urls == []
    assert correo.adjuntos == []
    assert correo.ip_origen is None
