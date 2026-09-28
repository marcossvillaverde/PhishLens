"""Pruebas de la preparación del corpus (sin descargar nada de internet)."""

import io
import tarfile

import requests

from phishlens.evaluacion.preparar import descargar_phishing, extraer_legitimos


class Respuesta:
    def __init__(self, codigo, contenido=b""):
        self.status_code, self.content = codigo, contenido


class SesionFalsa:
    """Simula Phishing Pot: algunas muestras no existen y dos son idénticas."""

    def __init__(self):
        self.pedidos = []

    def get(self, url, timeout=None):
        n = int(url.rsplit("-", 1)[1].split(".")[0])
        self.pedidos.append(n)
        if n % 5 == 0:
            return Respuesta(404)
        if n % 7 == 0:
            raise requests.ConnectionError()
        contenido = b"duplicado" if n % 3 == 0 else f"correo {n}".encode()
        return Respuesta(200, contenido)


def test_descarga_phishing_cantidad_exacta_sin_duplicados(tmp_path):
    guardados = descargar_phishing(10, tmp_path, SesionFalsa())
    assert len(guardados) == 10
    contenidos = [r.read_bytes() for r in guardados]
    assert len(set(contenidos)) == 10


def test_descarga_phishing_reproducible_y_reanudable(tmp_path):
    primera = descargar_phishing(5, tmp_path / "a", SesionFalsa())
    segunda = descargar_phishing(5, tmp_path / "b", SesionFalsa())
    assert [r.name for r in primera] == [r.name for r in segunda]   # misma semilla, misma muestra
    # Segunda ejecución sobre la misma carpeta: los ya guardados no se vuelven a pedir
    sesion = SesionFalsa()
    repetida = descargar_phishing(5, tmp_path / "a", sesion)
    ya_guardados = {int(r.stem.rsplit("-", 1)[1]) for r in primera}
    assert [r.name for r in repetida] == [r.name for r in primera]
    assert not ya_guardados & set(sesion.pedidos)


def _tar(tmp_path, miembros: dict[str, bytes]):
    ruta = tmp_path / "corpus.tar.bz2"
    with tarfile.open(ruta, "w:bz2") as tar:
        for nombre, datos in miembros.items():
            info = tarfile.TarInfo(nombre)
            info.size = len(datos)
            tar.addfile(info, io.BytesIO(datos))
    return ruta


def test_extraer_legitimos_ignora_cmds(tmp_path):
    ruta = _tar(tmp_path, {"easy_ham/0001.abc": b"uno", "easy_ham/0002.def": b"dos", "easy_ham/cmds": b"x"})
    guardados = extraer_legitimos(ruta, 10, tmp_path / "salida")
    assert sorted(r.name for r in guardados) == ["spamassassin-0001.eml", "spamassassin-0002.eml"]


def test_tar_malicioso_no_escribe_fuera(tmp_path):
    # Un tar con una ruta "../" intenta escribir fuera de la carpeta de destino
    ruta = _tar(tmp_path, {"easy_ham/0001.abc": b"bueno", "../../fuera.eml": b"malo"})
    guardados = extraer_legitimos(ruta, 10, tmp_path / "salida")
    assert [r.name for r in guardados] == ["spamassassin-0001.eml"]
    assert not (tmp_path / "fuera.eml").exists()
