"""Pruebas de los informes JSON y HTML (hito 7)."""

import json
from pathlib import Path

import phishlens.analisis as analisis
from phishlens.analisis import OpcionesAnalisis, analizar
from phishlens.config import Config
from phishlens.redteam.corpus import construir
from phishlens.report import a_diccionario, guardar_informes, indicadores

FIXTURES = Path(__file__).parent / "fixtures"
SIN_RED_SIN_IA = OpcionesAnalisis(en_linea=False, ia=False)


class ModeloFalso:
    nombre = "modelo falso"

    def __init__(self, explicacion="Suplanta a PayPal."):
        self.explicacion = explicacion

    def generar(self, sistema, mensaje):
        return json.dumps({
            "probabilidad_phishing": 0.95, "tipo_fraude": "robo_credenciales",
            "tacticas": ["urgencia"], "tecnicas_mitre": ["T1566.002"],
            "explicacion": self.explicacion, "recomendacion": "No hagas clic.",
        })


def _analizar_eml(tmp_path, eml: bytes, **opciones):
    ruta = tmp_path / "correo.eml"
    ruta.write_bytes(eml)
    return analizar(ruta, Config(), OpcionesAnalisis(en_linea=False, **opciones))


# --- JSON ---

def test_json_serializable_y_completo():
    r = analizar(FIXTURES / "phishing_simple.eml", Config(), SIN_RED_SIN_IA)
    datos = json.loads(json.dumps(a_diccionario(r)))
    assert datos["veredicto"]["final"] == "phishing"
    assert datos["correo"]["asunto"] == "Acción requerida: su cuenta será suspendida"
    assert len(datos["analisis"]["sha256_fichero"]) == 64
    assert datos["ia"] is None
    assert "bytes_originales" not in json.dumps(datos)


def test_indicadores_no_proponen_bloquear_dominios_legitimos():
    r = analizar(FIXTURES / "phishing_simple.eml", Config(), SIN_RED_SIN_IA)
    iocs = indicadores(r)
    assert "paypa1-verify.com" in iocs["dominios"]
    # Ni el dominio suplantado (paypal.com) ni un proveedor gratuito (gmail.com)
    assert "paypal.com" not in iocs["dominios"] and "gmail.com" not in iocs["dominios"]
    # La cuenta concreta del atacante sí, pero no la dirección suplantada de PayPal
    assert "soporte.paypal.cuentas@gmail.com" in iocs["direcciones_correo"]
    assert "servicio@paypal.com" not in iocs["direcciones_correo"]


# --- HTML ---

def test_html_escapa_el_contenido_del_atacante(tmp_path):
    eml = construir(asunto='<script>alert("xss")</script>',
                    html_extra='<p>Hola <img src="http://malo.example/x.png" onerror="alert(1)"></p>')
    r = _analizar_eml(tmp_path, eml, ia=False)
    html_ruta, _ = guardar_informes(r, tmp_path / "informes")
    html = html_ruta.read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_sin_enlaces_ni_recursos_externos(tmp_path):
    r = analizar(FIXTURES / "phishing_simple.eml", Config(), SIN_RED_SIN_IA)
    html = guardar_informes(r, tmp_path)[0].read_text(encoding="utf-8")
    assert "href=" not in html and "src=" not in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "hxxp://secure-login[.]paypa1-verify[.]com/acceso" in html


def test_html_con_analisis_de_ia(tmp_path, monkeypatch):
    monkeypatch.setattr(analisis, "crear_proveedor",
                        lambda config: ModeloFalso("Explicación con <b>etiquetas</b>."))
    r = analizar(FIXTURES / "phishing_simple.eml", Config(), OpcionesAnalisis(en_linea=False))
    html = guardar_informes(r, tmp_path)[0].read_text(encoding="utf-8")
    assert "Explicación con &lt;b&gt;etiquetas&lt;/b&gt;." in html
    assert "No hagas clic." in html and "T1566.002" in html


def test_html_si_la_ia_falla(tmp_path):
    # Config vacía: no hay OLLAMA_URL, así que la IA no está disponible
    r = analizar(FIXTURES / "phishing_simple.eml", Config(), OpcionesAnalisis(en_linea=False))
    html = guardar_informes(r, tmp_path)[0].read_text(encoding="utf-8")
    assert "no está disponible" in html
    # Aun así hay una recomendación para el usuario
    assert "No abras los enlaces" in html


def test_guardar_crea_ambos_ficheros(tmp_path):
    r = analizar(FIXTURES / "legitimo_simple.eml", Config(), SIN_RED_SIN_IA)
    html, json_ = guardar_informes(r, tmp_path / "nueva")
    assert html.is_file() and json_.is_file() and html.stem == json_.stem
