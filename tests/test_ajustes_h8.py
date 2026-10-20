"""
Pruebas de los ajustes hechos tras la evaluación con correos reales (hito 8).

Los ajustes corrigen falsos positivos observados en el conjunto de desarrollo:
  1. Sin red y sin cabecera de autenticación, la autenticación es DESCONOCIDA
     (la falta de datos no es un indicio).
  2. Un Reply-To a otro dominio corporativo es un indicio débil (listas de correo).
  3. Solo con indicios débiles (BAJA), el correo no pasa de LIMPIO.
"""

from phishlens.checks.autenticacion import comprobar_autenticacion
from phishlens.checks.heuristicas import comprobar_remitente
from phishlens.checks.modelos import Hallazgo, Severidad
from phishlens.evaluacion.preparar import descargar_phishing
from phishlens.parser import CorreoParseado, parsear_bytes
from phishlens.scoring import Veredicto, puntuar

CORREO_SIN_CABECERA = b"From: Ana <ana@ejemplo.org>\r\nTo: b@ejemplo.org\r\nSubject: hola\r\n\r\nQue tal."


def _codigos(hallazgos):
    return {h.codigo for h in hallazgos}


# --- 1. Autenticación desconocida ---

def test_sin_red_ni_cabecera_la_autenticacion_es_desconocida():
    resultado, hallazgos = comprobar_autenticacion(parsear_bytes(CORREO_SIN_CABECERA), en_linea=False)
    assert (resultado.spf, resultado.dkim, resultado.dmarc) == ("desconocido",) * 3
    assert _codigos(hallazgos) == {"AUTENTICACION_DESCONOCIDA"}
    assert all(h.severidad == Severidad.INFO for h in hallazgos)


def test_mecanismo_no_mencionado_es_desconocido():
    eml = (b"Authentication-Results: mx.x; spf=softfail smtp.mailfrom=a.com\r\n"
           + CORREO_SIN_CABECERA)
    resultado, hallazgos = comprobar_autenticacion(parsear_bytes(eml), en_linea=False)
    assert resultado.spf == "softfail" and resultado.dkim == "desconocido"
    assert _codigos(hallazgos) == {"SPF_SOFTFAIL"}


# --- 2. Reply-To ---

def test_reply_to_corporativo_es_indicio_debil():
    correo = CorreoParseado(remitente="noticias@tienda.es", reply_to="lista@servicio-listas.com")
    reply = next(h for h in comprobar_remitente(correo) if h.codigo == "REPLY_TO_DISTINTO")
    assert reply.severidad == Severidad.BAJA


def test_reply_to_gratuito_sigue_siendo_alto():
    correo = CorreoParseado(remitente="avisos@banco.es", reply_to="banco.soporte@gmail.com")
    reply = next(h for h in comprobar_remitente(correo) if h.codigo == "REPLY_TO_DISTINTO")
    assert reply.severidad == Severidad.ALTA


# --- 3. Indicios débiles ---

def _h(codigo, severidad):
    return Hallazgo(codigo, "x", severidad, "x")


def test_solo_indicios_debiles_no_pasan_de_limpio():
    debiles = [_h(f"B{i}", Severidad.BAJA) for i in range(5)]      # 25 puntos
    resultado = puntuar(debiles)
    assert resultado.puntuacion == 25 and resultado.veredicto == Veredicto.LIMPIO


def test_un_indicio_medio_con_debiles_si_es_sospechoso():
    hallazgos = [_h("M", Severidad.MEDIA), _h("B1", Severidad.BAJA)]  # 20 puntos
    assert puntuar(hallazgos).veredicto == Veredicto.SOSPECHOSO


# --- Separación de conjuntos ---

class SesionTodoOk:
    def get(self, url, timeout=None):
        n = url.rsplit("-", 1)[1].split(".")[0]
        return type("R", (), {"status_code": 200, "content": f"correo {n}".encode()})()


def test_conjunto_de_prueba_no_repite_correos_de_desarrollo(tmp_path):
    desarrollo = descargar_phishing(20, tmp_path / "dev", SesionTodoOk(), semilla=42)
    usados = {r.name for r in desarrollo}
    prueba = descargar_phishing(20, tmp_path / "test", SesionTodoOk(), semilla=2027, excluir=usados)
    assert len(prueba) == 20 and not usados & {r.name for r in prueba}
