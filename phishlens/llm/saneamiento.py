"""
Saneamiento del contenido del correo antes de enviarlo a la IA.

El texto del correo lo escribe el atacante, así que antes de que lo lea
el modelo de lenguaje:
  1. Se separa el texto VISIBLE del texto OCULTO en el HTML (display:none,
     tamaño de letra 0, texto blanco...). El oculto no se envía a la IA.
  2. Se buscan patrones típicos de prompt injection en todo el contenido.
  3. Se desactivan las URLs (hxxp://dominio[.]com) para que no sean clicables.
  4. Se sustituye la dirección del destinatario por [DESTINATARIO].
  5. Se trunca el texto para no desbordar el contexto del modelo.

Los hallazgos que genera (texto oculto, posible inyección) son deterministas
y suman riesgo en la puntuación, igual que el resto de comprobaciones.
"""

import re
import unicodedata
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

from phishlens.checks.modelos import Hallazgo, Severidad
from phishlens.parser import CorreoParseado

MAX_CARACTERES_CUERPO = 3000   # unos 1.000 tokens: deja margen en un contexto de 4.096

# Etiquetas cuyo contenido nunca ve el usuario
ETIQUETAS_INVISIBLES = ["script", "style", "head", "title", "noscript", "template", "meta"]

# Etiquetas de bloque: separan líneas en el texto visible
ETIQUETAS_BLOQUE = ["p", "div", "li", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6",
                    "blockquote", "section", "article", "header", "footer", "ul", "ol"]

# Estilos CSS que esconden texto (se comparan sin espacios y en minúsculas)
ESTILOS_OCULTOS = [
    r"display:none",
    r"visibility:hidden",
    r"opacity:0(\.0+)?(;|$)",
    r"font-size:0(px|pt|em|rem|%)?(;|$)",
    r"max-height:0(px)?(;|$)",
    r"(^|;)color:(#fff(fff)?|white|rgb\(255,255,255\))(;|$)",
]

# Patrones de prompt injection (se buscan sin tildes y en minúsculas)
PATRONES_INYECCION = [
    r"ignor\w*\s+(todas\s+)?(las\s+)?(instrucciones|indicaciones|reglas)",
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous\s+|prior\s+|above\s+)?instructions",
    r"(system|sistema)\s+prompt",
    r"you\s+are\s+now",
    r"actua\s+como\s+(un|una)\b",
    r"(sistema|herramienta|modelo|asistente|filtro)\s+de\s+(analisis|deteccion|seguridad)",
    r"(analysis|security|detection)\s+(system|tool|model|filter)",
    r"clasific\w*\s+(este\s+|el\s+)?(correo\s+|mensaje\s+|email\s+)?como\s+(seguro|legitimo|limpio|no\s+malicioso)",
    r"(classify|mark|label)\s+(this|the)\s+(email|message)\s+as\s+(safe|legitimate|clean|benign)",
    r"(este|el)\s+(correo|mensaje)\s+es\s+(legitimo|seguro)",
    r"(responde|respond|answer)\s+(solo|unicamente|only)\s+(con|with)",
]


@dataclass
class ContenidoSaneado:
    """Lo que se enviará a la IA, ya limpio, y los hallazgos detectados al limpiarlo."""
    texto_visible: str = ""
    texto_oculto: str = ""
    truncado: bool = False
    hallazgos: list[Hallazgo] = field(default_factory=list)


def _sin_tildes(texto: str) -> str:
    """Pasa a minúsculas y quita tildes para que 'Análisis' y 'analisis' coincidan."""
    normalizado = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in normalizado if not unicodedata.combining(c))


def _compactar(texto: str) -> str:
    """Quita espacios repetidos y líneas vacías sobrantes."""
    lineas = [" ".join(linea.split()) for linea in texto.splitlines()]
    return "\n".join(linea for linea in lineas if linea).strip()


def _es_oculto(etiqueta) -> bool:
    if etiqueta.has_attr("hidden") or etiqueta.get("aria-hidden") == "true":
        return True
    estilo = "".join(str(etiqueta.get("style", "")).lower().split())
    return any(re.search(patron, estilo) for patron in ESTILOS_OCULTOS)


def separar_visible_y_oculto(html: str) -> tuple[str, str]:
    """Devuelve (texto visible, texto oculto) de un cuerpo HTML."""
    soup = BeautifulSoup(html, "html.parser")
    for comentario in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comentario.extract()
    for nombre in ETIQUETAS_INVISIBLES:
        for etiqueta in soup.find_all(nombre):
            etiqueta.decompose()

    ocultos = []
    for etiqueta in soup.find_all(True):
        if etiqueta.decomposed:
            continue
        if _es_oculto(etiqueta):
            ocultos.append(etiqueta.get_text(" ", strip=True))
            etiqueta.decompose()

    # Saltos de línea donde el navegador los pondría (bloques y <br>), no dentro de <b> o <a>
    for salto in soup.find_all("br"):
        salto.replace_with("\n")
    for bloque in soup.find_all(ETIQUETAS_BLOQUE):
        bloque.insert_before("\n")
        bloque.append("\n")
    visible = _compactar(soup.get_text(""))
    oculto = _compactar("\n".join(t for t in ocultos if t))
    return visible, oculto


def desactivar_url(url: str) -> str:
    """http://a.b.com/x -> hxxp://a[.]b[.]com/x (no clicable, pero legible)."""
    url = re.sub(r"^http(s?)", lambda m: "hxxp" + m.group(1).lower(), url, flags=re.IGNORECASE)
    partes = url.split("/", 3)
    if len(partes) >= 3:
        partes[2] = partes[2].replace(".", "[.]")
    return "/".join(partes)


def desactivar_urls_en_texto(texto: str) -> str:
    return re.sub(r"https?://[^\s<>\"')\]]+", lambda m: desactivar_url(m.group(0)), texto, flags=re.IGNORECASE)


def seudonimizar(texto: str, destinatarios: list[str]) -> str:
    """Sustituye las direcciones del destinatario por [DESTINATARIO]."""
    for direccion in destinatarios:
        if direccion:
            texto = re.sub(re.escape(direccion), "[DESTINATARIO]", texto, flags=re.IGNORECASE)
    return texto


def buscar_inyeccion(texto: str) -> str | None:
    """Devuelve el fragmento sospechoso si el texto parece un intento de prompt injection."""
    plano = _sin_tildes(texto)
    for patron in PATRONES_INYECCION:
        coincidencia = re.search(patron, plano)
        if coincidencia:
            inicio = max(0, coincidencia.start() - 30)
            return " ".join(plano[inicio:coincidencia.end() + 30].split())
    return None


def sanear(correo: CorreoParseado) -> ContenidoSaneado:
    """Prepara el contenido del correo para la IA y detecta manipulaciones."""
    resultado = ContenidoSaneado()

    if correo.cuerpo_html:
        visible, oculto = separar_visible_y_oculto(correo.cuerpo_html)
    else:
        visible, oculto = _compactar(correo.cuerpo_texto), ""
    resultado.texto_oculto = oculto

    if len(oculto) >= 20:
        resultado.hallazgos.append(Hallazgo(
            "TEXTO_OCULTO", "contenido", Severidad.MEDIA,
            "El correo contiene texto escondido que el destinatario no ve (se ha excluido del análisis de IA).",
            oculto[:100] + ("..." if len(oculto) > 100 else ""),
        ))

    # Se busca inyección en TODO: texto visible, oculto, versión en texto plano y asunto
    for origen, texto in (("oculto", oculto), ("visible", visible),
                          ("texto plano", correo.cuerpo_texto), ("asunto", correo.asunto)):
        fragmento = buscar_inyeccion(texto)
        if fragmento:
            resultado.hallazgos.append(Hallazgo(
                "POSIBLE_PROMPT_INJECTION", "contenido", Severidad.ALTA,
                "El correo contiene instrucciones dirigidas a un sistema de análisis automático; "
                "es un intento de manipular a la IA.",
                f"({origen}) ...{fragmento}...",
            ))
            break

    texto = seudonimizar(desactivar_urls_en_texto(visible), correo.destinatarios)
    if len(texto) > MAX_CARACTERES_CUERPO:
        texto = texto[:MAX_CARACTERES_CUERPO] + "\n[... texto truncado ...]"
        resultado.truncado = True
    resultado.texto_visible = texto
    return resultado
