"""Pruebas del evaluador del hito 8 (con un corpus mínimo y un modelo simulado)."""

import csv
import hashlib
import json
import shutil
from pathlib import Path

import phishlens.evaluacion.evaluar as ev
from phishlens.evaluacion.evaluar import (
    ResultadoCorreo,
    configuraciones,
    ejecutar,
    metricas,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _corpus(tmp_path) -> Path:
    """Corpus con un phishing y un legítimo, a partir de los fixtures."""
    filas = []
    for nombre, etiqueta in (("phishing_simple.eml", "phishing"), ("legitimo_simple.eml", "legitimo")):
        destino = tmp_path / etiqueta / nombre
        destino.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / nombre, destino)
        filas.append({"fichero": f"{etiqueta}/{nombre}", "etiqueta": etiqueta, "fuente": "prueba",
                      "sha256": hashlib.sha256(destino.read_bytes()).hexdigest()})
    with (tmp_path / "manifiesto.csv").open("w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=["fichero", "etiqueta", "fuente", "sha256"])
        escritor.writeheader()
        escritor.writerows(filas)
    return tmp_path


class ModeloFalso:
    """Con datos técnicos dice 90 %; sin ellos (IA sola) dice 20 %. Cuenta las llamadas."""
    nombre = "modelo falso"

    def __init__(self):
        self.llamadas = 0
        self.mensajes = []

    def generar(self, sistema, mensaje):
        self.llamadas += 1
        self.mensajes.append(mensaje)
        prob = 0.2 if "No se proporcionan datos técnicos" in mensaje else 0.9
        return json.dumps({"probabilidad_phishing": prob, "tipo_fraude": "otro", "tacticas": [],
                           "tecnicas_mitre": [], "explicacion": "x", "recomendacion": "-"})


def test_metricas():
    pares = [(True, True)] * 8 + [(True, False)] * 2 + [(False, True)] * 1 + [(False, False)] * 9
    m = metricas(pares)
    assert (m["vp"], m["fn"], m["fp"], m["vn"]) == (8, 2, 1, 9)
    assert m["deteccion"] == 0.8 and m["falsos_positivos"] == 0.1
    assert round(m["precision"], 3) == round(8 / 9, 3) and m["exactitud"] == 0.85


def test_metricas_sin_datos_no_divide_por_cero():
    assert metricas([])["exactitud"] == 0.0


def test_solo_reglas(tmp_path):
    resultados = ejecutar(_corpus(tmp_path))
    por_nombre = {Path(r.fichero).name: r for r in resultados}
    assert por_nombre["phishing_simple.eml"].veredicto_reglas == "phishing"
    assert por_nombre["legitimo_simple.eml"].veredicto_reglas == "limpio"
    m = configuraciones(resultados)["Reglas (sospechoso o phishing)"]
    assert (m["vp"], m["fp"], m["vn"], m["fn"]) == (1, 0, 1, 0)


def test_con_ia_calcula_las_tres_configuraciones(tmp_path):
    modelo = ModeloFalso()
    resultados = ejecutar(_corpus(tmp_path), modelo)
    assert modelo.llamadas == 4                     # 2 correos x (con datos + solo contenido)
    # El modo "IA sola" no recibe el veredicto de las reglas
    sola = [m for m in modelo.mensajes if "No se proporcionan datos técnicos" in m]
    assert sola and all("veredicto_reglas" not in m for m in sola)
    pc = configuraciones(resultados)
    assert pc["IA sola, solo contenido (≥ 50 %)"]["vp"] == 0      # 20 % < 50 %
    assert pc["IA con datos técnicos (≥ 50 %)"]["vp"] == 1


def test_reanuda_sin_repetir_llamadas(tmp_path):
    corpus = _corpus(tmp_path)
    ejecutar(corpus, ModeloFalso())
    modelo = ModeloFalso()
    resultados = ejecutar(corpus, modelo)
    assert modelo.llamadas == 0 and len(resultados) == 2


def test_resumen_no_incluye_contenido_de_los_correos(tmp_path, monkeypatch):
    monkeypatch.setattr(ev, "RAIZ_PROYECTO", tmp_path)
    resultados = [
        ResultadoCorreo("phishing/a.eml", "phishing", "prueba", "x", 100, "phishing", ["DMARC_FAIL"]),
        ResultadoCorreo("legitimo/b.eml", "legitimo", "prueba", "y", 25, "sospechoso", ["REPLY_TO_DISTINTO"]),
    ]
    ruta = ev.guardar_resumen(resultados, configuraciones(resultados), "")
    texto = ruta.read_text(encoding="utf-8")
    assert "REPLY_TO_DISTINTO: 1" in texto          # causa del falso positivo
    assert "Acción requerida" not in texto          # nunca asuntos ni cuerpos


class ModeloCaido:
    """Simula que Ollama no responde. Mismo nombre que ModeloFalso: comparten fichero de resultados."""
    nombre = "modelo falso"

    def generar(self, sistema, mensaje):
        from phishlens.llm.proveedores import ErrorProveedor
        raise ErrorProveedor("no se puede conectar con Ollama")


def test_reintenta_los_correos_en_los_que_fallo_la_ia(tmp_path):
    corpus = _corpus(tmp_path)
    fallidos = ejecutar(corpus, ModeloCaido())
    assert all(r.error_ia for r in fallidos)
    # Con el modelo funcionando, los dos correos se vuelven a analizar
    modelo = ModeloFalso()
    resultados = ejecutar(corpus, modelo)
    assert modelo.llamadas == 4
    assert not any(r.error_ia for r in resultados)
    # Y una tercera vez ya salen de la caché, sin llamar al modelo
    otro = ModeloFalso()
    ejecutar(corpus, otro)
    assert otro.llamadas == 0


def test_guarda_el_detalle_de_la_respuesta_de_la_ia(tmp_path):
    resultados = ejecutar(_corpus(tmp_path), ModeloFalso())
    for r in resultados:
        assert r.tipo_fraude == "otro" and r.tipo_fraude_sola == "otro"
        assert r.explicacion == "x"
        assert r.tacticas == [] and r.tecnicas_mitre == []


class ModeloConProbabilidad:
    """Devuelve siempre la misma probabilidad de phishing."""
    nombre = "modelo umbral"

    def __init__(self, prob):
        self.prob = prob

    def generar(self, sistema, mensaje):
        return json.dumps({"probabilidad_phishing": self.prob, "tipo_fraude": "otro", "tacticas": [],
                           "tecnicas_mitre": [], "explicacion": "x", "recomendacion": "-"})


def _sistema_con_probabilidad(prob):
    """Veredicto final de un correo legítimo (limpio para las reglas) con una IA que dice `prob`."""
    ruta = FIXTURES / "legitimo_simple.eml"
    fila = {"fichero": "legitimo_simple.eml", "etiqueta": "legitimo", "fuente": "prueba",
            "sha256": hashlib.sha256(ruta.read_bytes()).hexdigest()}
    r = ev.evaluar_correo(ruta, fila, ModeloConProbabilidad(prob))
    assert r.veredicto_reglas == "limpio"
    return r.veredicto_sistema


def test_h8b_ia_con_80_por_ciento_no_sube_el_veredicto():
    # El 70-80 % es la respuesta de "no estoy seguro" del modelo: no basta para alertar
    assert _sistema_con_probabilidad(0.8) == "limpio"


def test_h8b_ia_muy_segura_si_sube_el_veredicto():
    assert _sistema_con_probabilidad(0.9) == "sospechoso"


def test_cache_con_lineas_danadas_no_detiene_la_evaluacion(tmp_path):
    corpus = _corpus(tmp_path)
    ejecutar(corpus, ModeloFalso())
    cache = next(corpus.glob("resultados_*.jsonl"))
    # Simula una escritura cortada: una línea a medias y otra con bytes nulos
    with cache.open("a", encoding="utf-8") as f:
        f.write('{"fichero": "a medias\n\x00\x00\x00\n')
    modelo = ModeloFalso()
    resultados = ejecutar(corpus, modelo)
    assert len(resultados) == 2 and modelo.llamadas == 0
