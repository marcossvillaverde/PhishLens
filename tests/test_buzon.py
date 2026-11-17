"""
Pruebas de la vigilancia de buzón (H10) con un servidor IMAP simulado:
no se necesita ninguna cuenta real ni conexión a internet.
"""

from pathlib import Path

import pytest

from phishlens import buzon
from phishlens.analisis import OpcionesAnalisis, analizar
from phishlens.buzon import ErrorBuzon, revisar
from phishlens.config import cargar_config

FIXTURES = Path(__file__).parent / "fixtures"
PHISHING = (FIXTURES / "phishing_simple.eml").read_bytes()
LEGITIMO = (FIXTURES / "legitimo_simple.eml").read_bytes()


def analizador(ruta):
    """El análisis real de PhishLens, sin red, sin reputación y sin IA."""
    return analizar(ruta, cargar_config(), OpcionesAnalisis(en_linea=False, reputacion=False, ia=False))


class ServidorFalso:
    """Imita las respuestas de imaplib y registra todo lo que se le pide."""

    def __init__(self, correos, gmail=True, uidvalidity=1):
        self.correos = dict(correos)
        self.capabilities = ("IMAP4REV1", "X-GM-EXT-1") if gmail else ("IMAP4REV1",)
        self.uidvalidity = uidvalidity
        self.etiquetas = {}
        self.marcados_leidos = set()
        self.comandos = []
        self.llamadas = []
        self.readonly = None

    def select(self, buzon, readonly=False):
        self.readonly = readonly
        return "OK", [str(len(self.correos)).encode()]

    def response(self, codigo):
        return codigo, [str(self.uidvalidity).encode()]

    def uid(self, comando, *args):
        self.comandos.append(comando)
        self.llamadas.append((comando, *args))
        if comando == "SEARCH":
            uids = sorted(self.correos)
            if args[-1] != "ALL":
                desde = int(args[-1].split(":")[0])
                # Peculiaridad real de IMAP: "n:*" devuelve el último aunque sea menor que n
                uids = [u for u in uids if u >= desde] or uids[-1:]
            return "OK", [" ".join(map(str, uids)).encode()]
        if comando == "FETCH":
            uid, que = int(args[0]), args[1]
            if "RFC822.SIZE" in que:
                return "OK", [f"1 (UID {uid} RFC822.SIZE {len(self.correos[uid])})".encode()]
            if "BODY[]" in que:                     # sin PEEK: el servidor lo marcaría como leído
                self.marcados_leidos.add(uid)
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(self.correos[uid])}}}".encode(), self.correos[uid]), b")"]
        if comando == "STORE":
            if self.readonly:
                return "NO", [b"buzon en solo lectura"]
            self.etiquetas.setdefault(int(args[0]), []).append(args[2])
            return "OK", [b""]
        return "BAD", [b"no implementado"]


@pytest.fixture
def estado(tmp_path):
    return tmp_path / "estado.json"


def test_primera_revision_no_toca_los_correos_existentes(estado):
    servidor = ServidorFalso({1: LEGITIMO, 2: PHISHING})
    assert revisar(servidor, estado, analizador) == []
    assert servidor.etiquetas == {} and estado.exists()


def test_correo_nuevo_se_analiza_y_etiqueta_sin_marcarlo_como_leido(estado):
    servidor = ServidorFalso({1: LEGITIMO})
    revisar(servidor, estado, analizador)
    servidor.correos[2] = PHISHING
    servidor.correos[3] = LEGITIMO
    revisados = revisar(servidor, estado, analizador)
    assert [(r.uid, r.veredicto) for r in revisados] == [(2, "phishing"), (3, "limpio")]
    assert servidor.etiquetas == {2: ['("PhishLens/Phishing")'], 3: ['("PhishLens/Limpio")']}
    assert servidor.marcados_leidos == set()
    assert set(servidor.comandos) <= buzon.COMANDOS_PERMITIDOS
    # Una tercera revisión ya no repite nada (aunque IMAP devuelva el último en "n:*")
    assert revisar(servidor, estado, analizador) == []


def test_modo_prueba_no_modifica_nada(estado):
    servidor = ServidorFalso({1: LEGITIMO, 2: PHISHING})
    revisados = revisar(servidor, estado, analizador, prueba=True, ultimos=2)
    assert [r.veredicto for r in revisados] == ["limpio", "phishing"]
    assert servidor.readonly is True
    assert servidor.etiquetas == {} and "STORE" not in servidor.comandos
    assert not estado.exists()


def test_ultimos_analiza_los_n_ultimos_existentes(estado):
    servidor = ServidorFalso({1: LEGITIMO, 2: LEGITIMO, 3: PHISHING})
    revisados = revisar(servidor, estado, analizador, ultimos=2)
    assert [r.uid for r in revisados] == [2, 3]


def test_servidor_no_gmail_usa_palabra_clave(estado):
    servidor = ServidorFalso({1: LEGITIMO}, gmail=False)
    revisar(servidor, estado, analizador)
    servidor.correos[2] = PHISHING
    revisar(servidor, estado, analizador)
    assert servidor.etiquetas == {2: ["(PhishLens_phishing)"]}


def test_cambio_de_uidvalidity_no_reanaliza_todo(estado):
    servidor = ServidorFalso({1: LEGITIMO, 2: PHISHING}, uidvalidity=1)
    revisar(servidor, estado, analizador)
    servidor.uidvalidity = 2                        # el servidor renumeró el buzón
    assert revisar(servidor, estado, analizador) == []


def test_correo_demasiado_grande_no_se_descarga(estado, monkeypatch):
    servidor = ServidorFalso({1: LEGITIMO})
    revisar(servidor, estado, analizador)
    servidor.correos[2] = PHISHING
    monkeypatch.setattr(buzon, "TAMANO_MAXIMO", 10)
    revisados = revisar(servidor, estado, analizador)
    assert revisados[0].error and servidor.etiquetas == {}
    assert ("FETCH", "2", "(BODY.PEEK[])") not in servidor.llamadas


@pytest.mark.parametrize("comando, args", [
    ("EXPUNGE", ()),
    ("COPY", ("1", "Trash")),
    ("MOVE", ("1", "Trash")),
    ("STORE", ("1", "+FLAGS", r"(\Deleted)")),
    ("STORE", ("1", "+FLAGS", r"(\Seen)")),
    ("STORE", ("1", "-X-GM-LABELS", '("PhishLens/Phishing")')),
    ("STORE", ("1", "+X-GM-LABELS", '("\\\\Trash")')),
    ("FETCH", ("1", "(BODY[])")),
])
def test_lista_blanca_rechaza_acciones_peligrosas(comando, args):
    servidor = ServidorFalso({1: LEGITIMO})
    with pytest.raises(ErrorBuzon):
        buzon._uid(servidor, comando, *args)
    assert servidor.comandos == []                  # ni siquiera llega al servidor


def test_el_nombre_del_estado_no_muestra_la_direccion():
    ruta = buzon.ruta_estado("alguien@gmail.com")
    assert "alguien" not in ruta.name and "gmail" not in ruta.name
