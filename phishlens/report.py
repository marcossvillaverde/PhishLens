"""
Generación de informes del análisis (hito 7).

  - JSON: para integrar con otras herramientas (SIEM, TheHive, scripts).
    Incluye las URLs reales, porque son indicadores (IOCs) que otras
    herramientas necesitan para buscar o bloquear.
  - HTML: para personas (el analista o el usuario que reportó el correo).
    Es un fichero autónomo que se abre sin conexión.

Seguridad del informe HTML:
  - Todo el texto del correo y de la IA se escapa con html.escape: un asunto
    como "<script>..." se ve como texto y nunca se ejecuta.
  - No contiene ningún enlace: las URLs aparecen desactivadas (hxxp://a[.]com).
  - Una política CSP en el propio fichero prohíbe scripts, imágenes y cualquier
    carga externa, como segunda barrera si algo escapara al punto anterior.
"""

import json
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from phishlens.analisis import VERSION, ResultadoAnalisis
from phishlens.checks.heuristicas import CORREO_GRATUITO, MARCAS
from phishlens.checks.modelos import Severidad, dominio_de_correo, dominio_organizativo
from phishlens.llm.saneamiento import desactivar_url, desactivar_urls_en_texto
from phishlens.scoring import Veredicto

ORDEN_SEVERIDAD = list(Severidad)

NOMBRES_SEVERIDAD = {
    Severidad.CRITICA: "Crítica", Severidad.ALTA: "Alta", Severidad.MEDIA: "Media",
    Severidad.BAJA: "Baja", Severidad.INFO: "Informativo",
}

NOMBRES_TACTICA = {
    "urgencia": "urgencia", "miedo": "miedo", "autoridad": "autoridad",
    "suplantacion_marca": "suplantación de marca", "recompensa": "recompensa",
    "curiosidad": "curiosidad", "peticion_credenciales": "petición de credenciales",
    "peticion_pago": "petición de pago", "peticion_secreto": "petición de secreto",
    "manipulacion_ia": "manipulación de la IA",
}

NOMBRES_VEREDICTO = {
    Veredicto.PHISHING: "Phishing",
    Veredicto.SOSPECHOSO: "Sospechoso",
    Veredicto.LIMPIO: "Sin indicios de phishing",
}

# Qué hacer si la IA no está disponible para redactar la recomendación
RECOMENDACION_POR_DEFECTO = {
    Veredicto.PHISHING: "No abras los enlaces ni los adjuntos, no respondas y reporta el correo al equipo de seguridad.",
    Veredicto.SOSPECHOSO: "No interactúes con el correo hasta que el equipo de seguridad lo revise.",
    Veredicto.LIMPIO: "No se han encontrado indicios de ataque. Si algo te resulta extraño, consúltalo igualmente.",
}


# ---------------------------------------------------------------- JSON

# Dominios que nunca se proponen para bloquear: servicios de correo gratuito y dominios
# oficiales de las marcas (en una suplantación, la marca es la víctima, no el atacante)
DOMINIOS_NO_BLOQUEABLES = set(CORREO_GRATUITO) | {d for lista in MARCAS.values() for d in lista}


def indicadores(resultado: ResultadoAnalisis) -> dict[str, list[str]]:
    """
    Indicadores observados en el correo, sin duplicados.

    Se excluyen los dominios de correo gratuito y los oficiales de las marcas:
    si un SOC bloqueara automáticamente estos indicadores, bloquear gmail.com
    o paypal.com sería un desastre. Las direcciones concretas sí se incluyen.
    """
    correo = resultado.correo
    urls = list(dict.fromkeys(u.url for u in correo.urls))
    dominios = [dominio_organizativo((urlparse(u).hostname or "").lower()) for u in urls]
    dominios += [dominio_organizativo(dominio_de_correo(d))
                 for d in (correo.remitente, correo.reply_to, correo.return_path) if d]
    # Las direcciones de correo gratuito sí se incluyen: son cuentas concretas del atacante
    oficiales = {d for lista in MARCAS.values() for d in lista} - set(CORREO_GRATUITO)
    direcciones = [d.lower() for d in (correo.remitente, correo.reply_to, correo.return_path)
                   if d and dominio_organizativo(dominio_de_correo(d)) not in oficiales]
    return {
        "urls": urls,
        "dominios": list(dict.fromkeys(d for d in dominios if d and d not in DOMINIOS_NO_BLOQUEABLES)),
        "direcciones_correo": list(dict.fromkeys(direcciones)),
        "ips": [correo.ip_origen] if correo.ip_origen else [],
        "sha256": list(dict.fromkeys(a.sha256 for a in correo.adjuntos)),
    }


def a_diccionario(resultado: ResultadoAnalisis) -> dict:
    """Convierte el resultado en un diccionario serializable a JSON."""
    correo, ia = resultado.correo, resultado.ia
    return {
        "herramienta": {"nombre": "PhishLens", "version": VERSION},
        "analisis": {
            "fecha": resultado.fecha.isoformat(timespec="seconds"),
            "fichero": resultado.fichero,
            "sha256_fichero": resultado.sha256_fichero,
            "opciones": vars(resultado.opciones),
        },
        "veredicto": {
            "final": resultado.final.veredicto.value,
            "reglas": resultado.final.veredicto_reglas.value,
            "puntuacion_reglas": resultado.final.puntuacion_reglas,
            "revision_manual": resultado.final.revision_manual,
            "motivo": resultado.final.motivo,
            "desglose": resultado.puntuacion.desglose,
        },
        "correo": {
            "remitente": correo.remitente,
            "remitente_nombre": correo.remitente_nombre,
            "reply_to": correo.reply_to,
            "return_path": correo.return_path,
            "destinatarios": correo.destinatarios,
            "asunto": correo.asunto,
            "fecha": correo.fecha,
            "message_id": correo.message_id,
            "ip_origen": correo.ip_origen,
            "saltos_received": len(correo.received),
            "enlaces": [{"url": u.url, "texto_visible": u.texto_visible, "origen": u.origen} for u in correo.urls],
            "adjuntos": [vars(a) for a in correo.adjuntos],
        },
        "autenticacion": vars(resultado.autenticacion),
        "hallazgos": [
            {"codigo": h.codigo, "categoria": h.categoria, "severidad": h.severidad.value,
             "descripcion": h.descripcion, "evidencia": h.evidencia}
            for h in resultado.hallazgos
        ],
        "reputacion": [vars(r) for r in resultado.reputacion],
        "ia": None if ia is None else {
            "proveedor": ia.proveedor,
            "segundos": ia.segundos,
            "error": ia.error,
            "avisos_validacion": ia.avisos,
            "analisis": None if ia.analisis is None else {
                "probabilidad_phishing": ia.analisis.probabilidad_phishing,
                "tipo_fraude": ia.analisis.tipo_fraude,
                "tacticas": ia.analisis.tacticas,
                "tecnicas_mitre": ia.analisis.tecnicas_mitre,
                "explicacion": ia.analisis.explicacion,
                "recomendacion": ia.analisis.recomendacion,
            },
        },
        "indicadores": indicadores(resultado),
        "nota_indicadores": "Indicadores observados en el correo. Revísalos antes de bloquearlos: "
                            "el remitente visible puede ser una dirección suplantada.",
    }


def generar_json(resultado: ResultadoAnalisis, ruta: Path) -> Path:
    ruta.write_text(json.dumps(a_diccionario(resultado), ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


# ---------------------------------------------------------------- HTML

CSS = """
:root {
  --papel: #f5f7fa; --tinta: #17202b; --suave: #5b6675; --linea: #d6dce4;
  --acero: #2f5d8c; --rojo: #a61b1b; --ambar: #9a5a06; --verde: #1f6f43;
  --serif: Charter, "Bitstream Charter", "Sitka Text", Cambria, Georgia, serif;
  --sans: system-ui, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Mono", "DejaVu Sans Mono", Consolas, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--papel); color: var(--tinta); font: 16px/1.55 var(--sans); }
main { max-width: 860px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
h1, h2 { font-family: var(--serif); font-weight: 600; line-height: 1.2; }
h2 { font-size: 1.35rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem; border-bottom: 1px solid var(--linea); }
p { max-width: 70ch; }

.veredicto { border-left: 10px solid var(--color); background: #fff; padding: 1.5rem 1.75rem; }
.veredicto h1 { color: var(--color); font-size: 2.6rem; margin: 0 0 .25rem; }
.veredicto .asunto { color: var(--suave); margin: 0 0 1.25rem; }
.escala { position: relative; height: 12px; background: linear-gradient(90deg, #e3eee8 0 20%, #f6ecd9 20% 50%, #f5e0de 50% 100%); }
.escala .marca { position: absolute; top: -5px; width: 4px; height: 22px; background: var(--tinta); }
.escala-texto { display: flex; justify-content: space-between; color: var(--suave); font-size: .8rem; margin-top: .35rem; }
.puntuacion { font-family: var(--serif); font-size: 1.1rem; margin: 1rem 0 .25rem; }
.revision { display: inline-block; margin-top: .75rem; padding: .2rem .6rem; border: 1px solid var(--ambar); color: var(--ambar); font-size: .9rem; }

.accion { background: #fff; border: 1px solid var(--linea); padding: 1rem 1.25rem; font-size: 1.1rem; }
.nota { color: var(--suave); font-size: .9rem; }
.etiquetas span { display: inline-block; margin: 0 .35rem .35rem 0; padding: .1rem .5rem; border: 1px solid var(--linea); background: #fff; font-size: .9rem; }

table { width: 100%; border-collapse: collapse; background: #fff; font-size: .95rem; }
th, td { text-align: left; vertical-align: top; padding: .5rem .65rem; border-bottom: 1px solid var(--linea); }
th { color: var(--suave); font-weight: 600; }
td.dato, .dato { font-family: var(--mono); font-size: .85rem; overflow-wrap: anywhere; }
.sev { font-weight: 600; white-space: nowrap; }
.sev-critica { color: var(--rojo); } .sev-alta { color: var(--rojo); } .sev-media { color: var(--ambar); }
.sev-baja { color: var(--verde); } .sev-info { color: var(--suave); font-weight: 400; }
tr.info td { color: var(--suave); }

details { background: #fff; border: 1px solid var(--linea); margin: .75rem 0; }
summary { cursor: pointer; padding: .75rem 1rem; font-family: var(--serif); font-size: 1.1rem; }
summary:focus-visible { outline: 3px solid var(--acero); outline-offset: 2px; }
details > div { padding: 0 1rem 1rem; }
footer { margin-top: 3rem; color: var(--suave); font-size: .85rem; }

@media (max-width: 600px) {
  .veredicto h1 { font-size: 2rem; }
  th, td { padding: .4rem; }
}
@media print {
  body { background: #fff; }
  details { border: none; }
  details > div { display: block; }
}
"""

COLOR_VEREDICTO = {Veredicto.PHISHING: "var(--rojo)", Veredicto.SOSPECHOSO: "var(--ambar)",
                   Veredicto.LIMPIO: "var(--verde)"}


def _e(valor) -> str:
    """Escapa cualquier valor para insertarlo en el HTML."""
    return escape(str(valor if valor is not None else ""), quote=True)


def _tabla(cabeceras: list[str], filas: list[list[str]], vacio: str) -> str:
    if not filas:
        return f'<p class="nota">{_e(vacio)}</p>'
    th = "".join(f"<th>{_e(c)}</th>" for c in cabeceras)
    cuerpo = "".join("<tr>" + "".join(celda for celda in fila) + "</tr>" for fila in filas)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{cuerpo}</tbody></table>"


def _celda(valor, clase: str = "") -> str:
    atributo = f' class="{clase}"' if clase else ""
    return f"<td{atributo}>{_e(valor)}</td>"


def _seccion_veredicto(r: ResultadoAnalisis) -> str:
    final = r.final
    color = COLOR_VEREDICTO[final.veredicto]
    posicion = min(100, max(0, final.puntuacion_reglas))
    revision = '<div class="revision">Revisión manual recomendada</div>' if final.revision_manual else ""
    return f"""
<section class="veredicto" style="--color: {color}">
  <h1>{_e(NOMBRES_VEREDICTO[final.veredicto])}</h1>
  <p class="asunto">{_e(r.correo.asunto or "(sin asunto)")}</p>
  <div class="escala" role="img" aria-label="Riesgo {posicion} sobre 100">
    <div class="marca" style="left: calc({posicion}% - 2px)"></div>
  </div>
  <div class="escala-texto"><span>0</span><span>20</span><span>50</span><span>100</span></div>
  <p class="puntuacion">Riesgo según las reglas: {posicion} de 100</p>
  <p>{_e(final.motivo)}</p>
  {revision}
</section>"""


def _seccion_ia(r: ResultadoAnalisis) -> str:
    ia = r.ia
    recomendacion = RECOMENDACION_POR_DEFECTO[r.final.veredicto]
    if ia and ia.analisis and ia.analisis.recomendacion:
        recomendacion = ia.analisis.recomendacion

    html = f'<h2>Qué debes hacer</h2><p class="accion">{_e(recomendacion)}</p>'

    if ia is None:
        return html
    if ia.analisis is None:
        return html + f'<h2>Por qué</h2><p class="nota">El análisis de IA no está disponible: {_e(ia.error)}</p>'

    a = ia.analisis
    tacticas = "".join(f"<span>{_e(NOMBRES_TACTICA.get(t, t))}</span>" for t in a.tacticas) or "<span>ninguna</span>"
    mitre = "".join(f"<span>{_e(t)}</span>" for t in a.tecnicas_mitre) or "<span>ninguna</span>"
    return html + f"""
<h2>Por qué</h2>
<p>{_e(a.explicacion)}</p>
<p class="nota">Explicación generada por IA ({_e(ia.proveedor)}), que estima una probabilidad de phishing del {a.probabilidad_phishing:.0%}.
El veredicto lo deciden las reglas; la IA puede subirlo, pero nunca bajarlo.</p>
<p><strong>Técnicas de engaño:</strong></p><div class="etiquetas">{tacticas}</div>
<p><strong>MITRE ATT&amp;CK:</strong></p><div class="etiquetas">{mitre}</div>"""


def _seccion_hallazgos(r: ResultadoAnalisis) -> str:
    ordenados = sorted(r.hallazgos, key=lambda h: ORDEN_SEVERIDAD.index(h.severidad), reverse=True)
    filas = []
    for h in ordenados:
        clase_fila = ' class="info"' if h.severidad == Severidad.INFO else ""
        filas.append(
            f'<tr{clase_fila}><td class="sev sev-{h.severidad.value}">{_e(NOMBRES_SEVERIDAD[h.severidad])}</td>'
            f"<td>{_e(h.descripcion)}</td><td class=\"dato\">{_e(desactivar_urls_en_texto(h.evidencia) or '-')}</td></tr>"
        )
    tabla = (f"<table><thead><tr><th>Gravedad</th><th>Indicio</th><th>Evidencia</th></tr></thead>"
             f"<tbody>{''.join(filas)}</tbody></table>") if filas else '<p class="nota">No se ha encontrado ningún indicio.</p>'
    return f"<h2>Indicios encontrados</h2>{tabla}"


def _seccion_correo(r: ResultadoAnalisis) -> str:
    c, a = r.correo, r.autenticacion
    fuente = "consulta DNS propia" if a.fuente == "en_linea" else "cabecera del servidor receptor"
    filas = [
        ["Remitente", f"{c.remitente_nombre} <{c.remitente}>"],
        ["Responder a", c.reply_to or "(igual que el remitente)"],
        ["Remitente técnico (Return-Path)", c.return_path or "-"],
        ["Para", ", ".join(c.destinatarios) or "-"],
        ["Fecha", c.fecha or "-"],
        ["IP de origen", c.ip_origen or "no encontrada"],
        ["SPF / DKIM / DMARC", f"{a.spf} / {a.dkim} / {a.dmarc} ({fuente})"],
    ]
    cuerpo = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in filas)
    return f"<h2>El correo</h2><table><tbody>{cuerpo}</tbody></table>"


def _detalles(r: ResultadoAnalisis) -> str:
    c = r.correo
    enlaces = _tabla(["Destino real (desactivado)", "Texto que ve el usuario"],
                     [[_celda(desactivar_url(u.url), "dato"),
                       _celda(desactivar_urls_en_texto(u.texto_visible) or "-")] for u in c.urls],
                     "El correo no contiene enlaces.")
    adjuntos = _tabla(["Nombre", "Tipo", "Tamaño", "SHA-256"],
                      [[_celda(a.nombre), _celda(a.tipo_mime), _celda(f"{a.tamano} B"), _celda(a.sha256, "dato")]
                       for a in c.adjuntos],
                      "El correo no tiene adjuntos.")

    filas_rep = []
    for x in r.reputacion:
        if x.error:
            estado = f"error: {x.error}"
        elif not x.encontrado:
            estado = "sin datos"
        elif x.servicio == "virustotal":
            estado = f"{x.datos.get('maliciosos', 0)} motores lo marcan como malicioso"
        elif x.servicio == "abuseipdb":
            estado = f"puntuación de abuso {x.datos.get('puntuacion_abuso', 0)}/100"
        else:
            estado = f"{x.datos.get('escaneos_previos', 0)} escaneos previos"
        filas_rep.append([_celda(x.servicio), _celda(x.tipo),
                          _celda(desactivar_urls_en_texto(x.indicador), "dato"), _celda(estado)])
    reputacion = _tabla(["Servicio", "Tipo", "Indicador", "Resultado"], filas_rep,
                        "No se consultaron servicios de reputación.")

    iocs = indicadores(r)
    lista_iocs = "".join(
        f"<tr><th>{_e(nombre)}</th><td class=\"dato\">{'<br>'.join(_e(desactivar_url(v) if tipo == 'urls' else v) for v in valores) or '-'}</td></tr>"
        for tipo, nombre, valores in (("urls", "URLs", iocs["urls"]), ("dominios", "Dominios", iocs["dominios"]),
                                      ("direcciones_correo", "Direcciones de correo", iocs["direcciones_correo"]),
                                      ("ips", "IPs", iocs["ips"]), ("sha256", "SHA-256", iocs["sha256"]))
    )

    ia = r.ia
    meta = [
        ["Fichero analizado", r.fichero],
        ["SHA-256 del fichero", r.sha256_fichero],
        ["Fecha del análisis", r.fecha.strftime("%d/%m/%Y %H:%M:%S %z")],
        ["Versión de PhishLens", VERSION],
        ["Consultas DNS", "sí" if r.opciones.en_linea else "no"],
        ["Servicios de reputación", "sí" if r.opciones.reputacion and r.opciones.en_linea else "no"],
        ["Modelo de IA", f"{ia.proveedor} ({ia.segundos} s)" if ia else "no usado"],
    ]
    if ia and ia.avisos:
        meta.append(["Ajustes a la respuesta de la IA", "; ".join(ia.avisos)])
    if r.saneado.texto_oculto:
        meta.append(["Texto oculto excluido del análisis de IA", desactivar_urls_en_texto(r.saneado.texto_oculto[:500])])
    tabla_meta = "".join(f"<tr><th>{_e(k)}</th><td class=\"dato\">{_e(v)}</td></tr>" for k, v in meta)

    return f"""
<h2>Detalles técnicos</h2>
<details><summary>Enlaces ({len(c.urls)})</summary><div>{enlaces}</div></details>
<details><summary>Adjuntos ({len(c.adjuntos)})</summary><div>{adjuntos}</div></details>
<details><summary>Reputación ({len(r.reputacion)} consultas)</summary><div>{reputacion}</div></details>
<details><summary>Indicadores observados</summary><div>
<p class="nota">Revísalos antes de bloquearlos: el remitente visible puede ser una dirección suplantada.
No se incluyen dominios de correo gratuito ni los oficiales de las marcas suplantadas.</p>
<table><tbody>{lista_iocs}</tbody></table></div></details>
<details><summary>Datos del análisis</summary><div><table><tbody>{tabla_meta}</tbody></table></div></details>"""


def generar_html(resultado: ResultadoAnalisis, ruta: Path) -> Path:
    titulo = f"{NOMBRES_VEREDICTO[resultado.final.veredicto]}: {resultado.correo.asunto or resultado.fichero}"
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(titulo)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
{_seccion_veredicto(resultado)}
{_seccion_ia(resultado)}
{_seccion_hallazgos(resultado)}
{_seccion_correo(resultado)}
{_detalles(resultado)}
<footer>
  <p>Informe generado por PhishLens {_e(VERSION)} el {_e(resultado.fecha.strftime("%d/%m/%Y a las %H:%M"))}.
  Los enlaces aparecen desactivados a propósito (hxxp://dominio[.]com): no los copies en el navegador.</p>
</footer>
</main>
</body>
</html>
"""
    ruta.write_text(html, encoding="utf-8")
    return ruta


def guardar_informes(resultado: ResultadoAnalisis, carpeta: Path) -> tuple[Path, Path]:
    """Guarda el informe HTML y el JSON con el mismo nombre base."""
    carpeta.mkdir(parents=True, exist_ok=True)
    base = f"{Path(resultado.fichero).stem}_{resultado.fecha:%Y%m%d_%H%M%S}"
    return (generar_html(resultado, carpeta / f"{base}.html"),
            generar_json(resultado, carpeta / f"{base}.json"))
