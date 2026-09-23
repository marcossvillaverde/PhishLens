"""
Pruebas del módulo de enriquecimiento.

No se conectan a internet: las respuestas de las APIs se simulan con
una sesión falsa que devuelve lo que cada prueba necesita.
"""

from pathlib import Path

import requests

from phishlens.checks.modelos import Severidad
from phishlens.config import Config
from phishlens.enrichment.abuseipdb import ClienteAbuseIPDB
from phishlens.enrichment.base import Cache, LimitadorCuota
from phishlens.enrichment.enriquecer import enriquecer
from phishlens.enrichment.urlscan import ClienteUrlscan
from phishlens.enrichment.virustotal import ClienteVirusTotal, _id_url
from phishlens.parser import parsear_eml

FIXTURE = Path(__file__).parent / "fixtures" / "phishing_simple.eml"
AHORA = 1_790_000_000  # instante fijo para las pruebas (septiembre de 2026)


class RespuestaFalsa:
    def __init__(self, codigo, cuerpo):
        self.status_code = codigo
        self._cuerpo = cuerpo

    def json(self):
        if self._cuerpo is None:
            raise ValueError("sin JSON")
        return self._cuerpo


class SesionFalsa:
    """Devuelve respuestas según un fragmento de la URL pedida y cuenta las llamadas."""

    def __init__(self, respuestas, por_defecto=(404, {})):
        self.respuestas = respuestas
        self.por_defecto = por_defecto
        self.llamadas = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.llamadas.append(url)
        for fragmento, (codigo, cuerpo) in self.respuestas.items():
            if fragmento in url:
                return RespuestaFalsa(codigo, cuerpo)
        return RespuestaFalsa(*self.por_defecto)


class SesionSinRed:
    def get(self, *args, **kwargs):
        raise requests.ConnectionError("red caída")


def _vt(maliciosos, sospechosos=0, creacion=None):
    atributos = {"last_analysis_stats": {"malicious": maliciosos, "suspicious": sospechosos,
                                         "harmless": 50, "undetected": 20}}
    if creacion:
        atributos["creation_date"] = creacion
    return (200, {"data": {"attributes": atributos}})


def _limitador_sin_espera():
    return LimitadorCuota(maximo=1000, ventana=60, dormir=lambda s: None)


# --- Utilidades ---

def test_id_url_virustotal_sin_relleno():
    assert _id_url("http://a.com/") == "aHR0cDovL2EuY29tLw"


def test_cache_guarda_y_caduca(tmp_path):
    reloj = [1000.0]
    cache = Cache(tmp_path, duracion=60, reloj=lambda: reloj[0])
    cache.guardar("clave", {"x": 1})
    assert cache.obtener("clave") == {"x": 1}
    reloj[0] += 61
    assert cache.obtener("clave") is None


def test_limitador_espera_al_llegar_al_maximo():
    tiempo = [0.0]
    esperas = []

    def dormir(s):
        esperas.append(s)
        tiempo[0] += s

    limitador = LimitadorCuota(maximo=4, ventana=60, reloj=lambda: tiempo[0], dormir=dormir)
    for _ in range(4):
        limitador.esperar_turno()
    assert esperas == []           # las 4 primeras pasan sin esperar
    limitador.esperar_turno()
    assert esperas == [60.0]       # la quinta espera a que pase el minuto


# --- VirusTotal ---

def test_virustotal_url_maliciosa_y_cache(tmp_path):
    sesion = SesionFalsa({"/urls/": _vt(12)})
    cliente = ClienteVirusTotal("clave", Cache(tmp_path), sesion, _limitador_sin_espera())
    r1 = cliente.consultar_url("http://malo.example/")
    r2 = cliente.consultar_url("http://malo.example/")
    assert r1.encontrado and r1.datos["maliciosos"] == 12
    assert r2.desde_cache
    assert len(sesion.llamadas) == 1   # la segunda consulta no gasta cuota


def test_virustotal_desconocido_no_es_error(tmp_path):
    cliente = ClienteVirusTotal("clave", Cache(tmp_path), SesionFalsa({}), _limitador_sin_espera())
    r = cliente.consultar_hash("a" * 64)
    assert not r.encontrado and r.error == ""


def test_virustotal_sin_red_no_rompe(tmp_path):
    cliente = ClienteVirusTotal("clave", Cache(tmp_path), SesionSinRed(), _limitador_sin_espera())
    r = cliente.consultar_url("http://a.example/")
    assert r.error.startswith("sin conexión")


# --- AbuseIPDB y urlscan ---

def test_abuseipdb_extrae_puntuacion(tmp_path):
    sesion = SesionFalsa({"abuseipdb": (200, {"data": {"abuseConfidenceScore": 87, "totalReports": 40,
                                                       "countryCode": "RU", "isp": "X", "isWhitelisted": False}})})
    r = ClienteAbuseIPDB("clave", Cache(tmp_path), sesion).consultar_ip("203.0.113.50")
    assert r.datos["puntuacion_abuso"] == 87 and r.datos["pais"] == "RU"


def test_urlscan_historial(tmp_path):
    sesion = SesionFalsa({"urlscan": (200, {"total": 3, "results": [{"_id": "abc-123"}]})})
    r = ClienteUrlscan("clave", Cache(tmp_path), sesion).buscar_dominio("paypa1-verify.com")
    assert r.encontrado and r.datos["ultimo_informe"] == "https://urlscan.io/result/abc-123/"


# --- Orquestación y hallazgos ---

def _clientes(tmp_path, respuestas_vt, respuesta_abuse):
    cache = Cache(tmp_path)
    vt = ClienteVirusTotal("k", cache, SesionFalsa(respuestas_vt), _limitador_sin_espera())
    abuse = ClienteAbuseIPDB("k", cache, SesionFalsa({"abuseipdb": respuesta_abuse}))
    urlscan = ClienteUrlscan("k", cache, SesionFalsa({"urlscan": (200, {"total": 0, "results": []})}))
    return vt, abuse, urlscan


def test_enriquecer_genera_hallazgos(tmp_path):
    correo = parsear_eml(FIXTURE)
    hace_5_dias = AHORA - 5 * 86400
    vt, abuse, urlscan = _clientes(
        tmp_path,
        {"/urls/": _vt(9), "/domains/": _vt(0, creacion=hace_5_dias), "/files/": (404, {})},
        (200, {"data": {"abuseConfidenceScore": 75, "totalReports": 12}}),
    )
    resultados, hallazgos = enriquecer(correo, Config(carpeta_cache=tmp_path),
                                       vt, abuse, urlscan, reloj=lambda: AHORA)
    codigos = {h.codigo: h for h in hallazgos}
    assert codigos["URL_MALICIOSO_VT"].severidad == Severidad.CRITICA
    assert codigos["DOMINIO_RECIENTE"].severidad == Severidad.ALTA
    assert codigos["IP_ORIGEN_REPORTADA"].severidad == Severidad.ALTA
    assert "ADJUNTO_MALICIOSO_VT" not in codigos   # el hash no es conocido (404)
    # 1 URL + 1 dominio + 1 hash en VirusTotal, 1 IP en AbuseIPDB, 1 dominio en urlscan
    assert len(resultados) == 5


def test_enriquecer_sin_claves_solo_informa(tmp_path):
    correo = parsear_eml(FIXTURE)
    resultados, hallazgos = enriquecer(correo, Config(carpeta_cache=tmp_path))
    assert resultados == []
    assert hallazgos and all(h.severidad == Severidad.INFO for h in hallazgos)


def test_mensajes_de_error_http(tmp_path):
    cache = Cache(tmp_path)
    vt = ClienteVirusTotal("k", cache, SesionFalsa({}, por_defecto=(401, {})), _limitador_sin_espera())
    assert "rechazó la clave" in vt.consultar_url("http://a.example/").error
    vt = ClienteVirusTotal("k", cache, SesionFalsa({}, por_defecto=(429, {})), _limitador_sin_espera())
    assert "cuota" in vt.consultar_hash("b" * 64).error
    abuse = ClienteAbuseIPDB("k", cache, SesionFalsa({}, por_defecto=(422, {})))
    assert "no admite" in abuse.consultar_ip("203.0.113.50").error
