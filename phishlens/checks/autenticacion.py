"""
Comprobaciones de autenticación del remitente: SPF, DKIM y DMARC.

Hay dos fuentes de información:
  1. La cabecera Authentication-Results que añade el servidor que recibió
     el correo (lo que él opinó en su momento).
  2. Verificación propia en línea (consultas DNS reales), que no depende de
     fiarse de una cabecera que podría estar manipulada.

Con la opción --sin-red no se hace ninguna consulta DNS y se usa solo
la cabecera.
"""

import re
from dataclasses import dataclass

import dkim
import dns.resolver
import spf

from phishlens.checks.modelos import (
    Hallazgo,
    Severidad,
    dominio_de_correo,
    dominio_organizativo,
)
from phishlens.parser import CorreoParseado

TIMEOUT_DNS = 5  # segundos máximos por consulta DNS


@dataclass
class ResultadoAutenticacion:
    """Resumen de SPF, DKIM y DMARC para el informe."""
    spf: str = "none"             # pass, fail, softfail, neutral, none, permerror, temperror
    dkim: str = "none"            # pass, fail, none
    dmarc: str = "none"           # pass, fail, none
    politica_dmarc: str = ""      # none, quarantine, reject (la que publica el dominio)
    fuente: str = "cabecera"      # "cabecera" o "en_linea"


def leer_authentication_results(cabecera: str) -> dict[str, str]:
    """
    Extrae los resultados spf=, dkim= y dmarc= de la cabecera Authentication-Results.

    Ejemplo: "mx.x; spf=fail smtp.mailfrom=a.com; dkim=none" -> {"spf": "fail", "dkim": "none"}
    """
    resultados = {}
    for mecanismo in ("spf", "dkim", "dmarc"):
        coincidencia = re.search(rf"\b{mecanismo}=(\w+)", cabecera, re.IGNORECASE)
        if coincidencia:
            resultados[mecanismo] = coincidencia.group(1).lower()
    return resultados


def _helo_del_emisor(correo: CorreoParseado) -> str:
    """Obtiene el nombre con el que se presentó el servidor emisor (HELO)."""
    if not correo.received:
        return ""
    coincidencia = re.match(r"from\s+(\S+)", correo.received[-1], re.IGNORECASE)
    return coincidencia.group(1) if coincidencia else ""


def verificar_spf(correo: CorreoParseado) -> str:
    """Comprueba SPF consultando el DNS del dominio del remitente de sobre."""
    remitente_sobre = correo.return_path or correo.remitente
    if not correo.ip_origen or not remitente_sobre:
        return "none"
    try:
        resultado, _explicacion = spf.check2(
            i=correo.ip_origen,
            s=remitente_sobre,
            h=_helo_del_emisor(correo) or "desconocido",
            timeout=TIMEOUT_DNS,
        )
        return resultado
    except Exception:
        return "temperror"


def verificar_dkim(correo: CorreoParseado) -> tuple[str, str]:
    """
    Verifica la firma DKIM del correo.

    Devuelve (resultado, dominio_firmante). Si no hay firma, ("none", "").
    """
    firma = re.search(rb"^DKIM-Signature:.*?\bd=([^;\s]+)", correo.bytes_originales,
                      re.IGNORECASE | re.MULTILINE | re.DOTALL)
    if not firma:
        return "none", ""
    dominio_firmante = firma.group(1).decode(errors="replace").lower()
    try:
        valido = dkim.verify(correo.bytes_originales, timeout=TIMEOUT_DNS)
        return ("pass" if valido else "fail"), dominio_firmante
    except Exception:
        return "fail", dominio_firmante


def consultar_politica_dmarc(dominio: str) -> str:
    """Consulta el registro DMARC del dominio y devuelve su política (p=)."""
    if not dominio:
        return ""
    try:
        respuesta = dns.resolver.resolve(f"_dmarc.{dominio}", "TXT", lifetime=TIMEOUT_DNS)
    except Exception:
        return ""
    for registro in respuesta:
        texto = b"".join(registro.strings).decode(errors="replace")
        if texto.lower().startswith("v=dmarc1"):
            coincidencia = re.search(r"\bp=(\w+)", texto, re.IGNORECASE)
            return coincidencia.group(1).lower() if coincidencia else "none"
    return ""


def comprobar_autenticacion(
    correo: CorreoParseado, en_linea: bool = True
) -> tuple[ResultadoAutenticacion, list[Hallazgo]]:
    """
    Evalúa SPF, DKIM y DMARC y genera los hallazgos correspondientes.

    en_linea=False evita cualquier consulta de red (útil para pruebas o
    para analizar correos sin conexión).
    """
    resultado = ResultadoAutenticacion()
    cabecera = leer_authentication_results(correo.authentication_results)
    dominio_from = dominio_organizativo(dominio_de_correo(correo.remitente))

    if en_linea:
        resultado.fuente = "en_linea"
        resultado.spf = verificar_spf(correo)
        resultado.dkim, dominio_dkim = verificar_dkim(correo)
        resultado.politica_dmarc = consultar_politica_dmarc(dominio_from)

        # DMARC: pasa si SPF o DKIM pasan Y además están alineados con el From
        dominio_sobre = dominio_organizativo(dominio_de_correo(correo.return_path or correo.remitente))
        spf_alineado = resultado.spf == "pass" and dominio_sobre == dominio_from
        dkim_alineado = resultado.dkim == "pass" and dominio_organizativo(dominio_dkim) == dominio_from
        if not resultado.politica_dmarc:
            resultado.dmarc = "none"
        else:
            resultado.dmarc = "pass" if (spf_alineado or dkim_alineado) else "fail"
    else:
        resultado.spf = cabecera.get("spf", "none")
        resultado.dkim = cabecera.get("dkim", "none")
        resultado.dmarc = cabecera.get("dmarc", "none")

    hallazgos: list[Hallazgo] = []

    # --- SPF ---
    if resultado.spf == "fail":
        hallazgos.append(Hallazgo(
            "SPF_FAIL", "autenticacion", Severidad.ALTA,
            "El servidor que envió el correo no está autorizado por el dominio del remitente (SPF fail).",
            f"IP de origen: {correo.ip_origen}",
        ))
    elif resultado.spf == "softfail":
        hallazgos.append(Hallazgo(
            "SPF_SOFTFAIL", "autenticacion", Severidad.MEDIA,
            "El dominio del remitente indica que este servidor probablemente no está autorizado (SPF softfail).",
            f"IP {correo.ip_origen}",
        ))
    elif resultado.spf in ("none", "neutral", "permerror"):
        hallazgos.append(Hallazgo(
            "SPF_SIN_VALIDAR", "autenticacion", Severidad.BAJA,
            f"No se ha podido validar el remitente mediante SPF (resultado: {resultado.spf}).",
        ))

    # --- DKIM ---
    if resultado.dkim == "fail":
        hallazgos.append(Hallazgo(
            "DKIM_FAIL", "autenticacion", Severidad.ALTA,
            "La firma DKIM no es válida: el correo pudo ser modificado o la firma es falsa.",
        ))
    elif resultado.dkim == "none":
        hallazgos.append(Hallazgo(
            "DKIM_AUSENTE", "autenticacion", Severidad.BAJA,
            "El correo no lleva firma DKIM.",
        ))

    # --- DMARC ---
    if resultado.dmarc == "fail":
        severidad = Severidad.CRITICA if resultado.politica_dmarc in ("reject", "quarantine") else Severidad.ALTA
        hallazgos.append(Hallazgo(
            "DMARC_FAIL", "autenticacion", severidad,
            "El correo no supera DMARC: no se puede demostrar que venga del dominio que aparece en From.",
            f"Dominio {dominio_from}, política publicada: {resultado.politica_dmarc or 'desconocida'}",
        ))

    return resultado, hallazgos
