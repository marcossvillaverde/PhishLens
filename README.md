# PhishLens

Analizador de correos de phishing que combina **comprobaciones deterministas** (SPF, DKIM, DMARC,
heurísticas y reputación de indicadores) con un **modelo de lenguaje** que interpreta la ingeniería
social del mensaje y redacta una explicación en español.

Proyecto de la asignatura **Proyectos de Ciberseguridad** — Grado en Ingeniería de Software y
Ciberseguridad, U-tad, curso 2026-2027. Autor: Marcos Villaverde González.

> ⚠️ **Aviso de seguridad.** PhishLens analiza correos potencialmente maliciosos. Úsalo en una
> máquina virtual aislada, no abras nunca los correos de prueba con un cliente de correo y no
> ejecutes sus adjuntos. La herramienta solo los lee como texto y calcula los hashes de los adjuntos.

## Qué hace

Recibe un correo en formato `.eml` y devuelve un veredicto (**limpio**, **sospechoso** o **phishing**),
una puntuación de riesgo de 0 a 100, las evidencias que lo justifican y una explicación con la
recomendación para el usuario.

1. **Parser**: cabeceras, cadena `Received` e IP de origen, cuerpo, enlaces (destino real frente a
   texto visible) y adjuntos (solo hash).
2. **Autenticación**: SPF, DKIM y DMARC, con consultas DNS propias o leyendo `Authentication-Results`.
3. **Heurísticas**: dominios que imitan marcas, enlaces engañosos, `Reply-To` sospechosos, adjuntos peligrosos.
4. **Reputación**: VirusTotal, AbuseIPDB y urlscan.io. Solo consulta; nunca sube URLs ni ficheros.
5. **Saneamiento**: separa el texto oculto, detecta intentos de *prompt injection*, desactiva URLs y
   seudonimiza al destinatario antes de enviar nada a la IA.
6. **Puntuación** determinista del riesgo.
7. **IA**: un modelo local (Ollama) o la API de Anthropic analiza la ingeniería social. Su respuesta
   se valida contra un esquema JSON y listas permitidas.
8. **Combinación**: las reglas deciden y la IA interpreta. La IA puede subir el veredicto, **nunca bajarlo**.
9. **Informes** en la terminal, en HTML (escapado, sin enlaces, con CSP) y en JSON con los indicadores.

## Requisitos

- Linux (probado en Kali Linux) con **Python 3.12 o superior** (probado con Python 3.14).
- Opcional, para el análisis con IA: [Ollama](https://ollama.com) con un modelo descargado
  (probado con `qwen2.5:14b`), o una clave de la API de Anthropic.
- Opcional, para la reputación: claves gratuitas de VirusTotal, AbuseIPDB y urlscan.io.

Sin IA ni claves, la herramienta funciona igualmente con las comprobaciones deterministas.

## Instalación

```bash
git clone https://github.com/marcossvillaverde/PhishLens.git
cd PhishLens
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Edita `.env` y rellena lo que vayas a usar. **El fichero `.env` nunca se sube a Git.**

```ini
LLM_PROVIDER=ollama                 # "ollama" (local) o "anthropic" (API externa)
OLLAMA_URL=http://10.0.2.2:11434    # ver la sección de Ollama
OLLAMA_MODEL=qwen2.5:14b
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
```

### Ollama con PhishLens dentro de una máquina virtual

El montaje recomendado ejecuta Ollama en el equipo anfitrión (para usar su GPU) y PhishLens en una
VM de VirtualBox con **un único adaptador de red en modo NAT**:

1. En el anfitrión, instala Ollama y descarga el modelo: `ollama pull qwen2.5:14b`.
2. **No expongas Ollama a la red**: déjalo escuchando solo en `127.0.0.1` (configuración por defecto).
3. Desde la VM, VirtualBox traduce `10.0.2.2` al `localhost` del anfitrión, así que
   `OLLAMA_URL=http://10.0.2.2:11434` funciona sin abrir puertos. Compruébalo con:
   `curl http://10.0.2.2:11434/api/tags`.

## Uso

```bash
python -m phishlens.main correo.eml                   # análisis completo
python -m phishlens.main correo.eml --sin-ia          # sin modelo de lenguaje
python -m phishlens.main correo.eml --sin-reputacion  # sin VirusTotal, AbuseIPDB ni urlscan.io
python -m phishlens.main correo.eml --sin-red         # sin internet (Ollama local sí se usa)
python -m phishlens.main correo.eml --informe         # guarda informe HTML y JSON en reports/
```

Prueba rápida con los correos ficticios incluidos:

```bash
python -m phishlens.main tests/fixtures/phishing_simple.eml --informe
python -m phishlens.main tests/fixtures/legitimo_simple.eml
```

## Pruebas

```bash
python -m pytest -q
```

Las pruebas no necesitan red ni modelo de IA: las APIs y el modelo se simulan.

### Red team contra la IA

16 correos diseñados para manipular al modelo (instrucciones visibles y ocultas, delimitadores
falsos, JSON falso, caracteres invisibles, homoglifos...), comparando un analizador sin defensas con PhishLens:

```bash
python -m phishlens.redteam.evaluar
```

### Evaluación con correos reales

```bash
python -m phishlens.evaluacion.preparar                       # conjunto de desarrollo
python -m phishlens.evaluacion.preparar --conjunto prueba     # conjunto de prueba (sin solapamiento)
python -m phishlens.evaluacion.evaluar --conjunto prueba --sin-ia
python -m phishlens.evaluacion.evaluar --conjunto prueba      # con IA (unos 45 minutos)
```

Los correos se descargan en `samples/`, que está excluida de Git. Los resúmenes de resultados,
sin contenido de los correos, se guardan en `docs/resultados/`.

## Estructura
phishlens/
├── main.py # línea de comandos
├── analisis.py # orquestación del análisis
├── parser.py # descomposición del correo
├── checks/ # autenticación y heurísticas
├── enrichment/ # VirusTotal, AbuseIPDB, urlscan.io
├── llm/ # saneamiento, prompt, proveedores y validación de la IA
├── scoring.py # puntuación de riesgo
├── combinacion.py # combinación de reglas e IA
├── report.py # informes HTML y JSON
├── redteam/ # corpus de ataques contra la IA y su evaluación
└── evaluacion/ # corpus de correos reales y métricas
tests/ # pruebas automáticas y correos ficticios de prueba
docs/ # registro de uso de IA, cambios y resultados

## Uso de IA en el desarrollo

El desarrollo se ha realizado con apoyo de Claude (Anthropic). Todo el uso queda registrado en
[`docs/USO_IA.md`](docs/USO_IA.md).

## Datos de evaluación

- [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) — correos de phishing reales (CC BY-NC 4.0).
- [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) — correo legítimo (*easy_ham*).

Estos correos no se incluyen en el repositorio; se descargan con `phishlens.evaluacion.preparar`.
