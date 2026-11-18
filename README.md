# PhishLens

Analizador de correos de phishing que combina **comprobaciones deterministas** (SPF, DKIM, DMARC,
heurísticas y reputación de indicadores) con un **modelo de lenguaje local** que interpreta la
ingeniería social del mensaje y redacta una explicación en español. Incluye un modo que **vigila
un buzón de correo** y etiqueta automáticamente los mensajes que llegan.

Proyecto de la asignatura **Proyectos de Ciberseguridad** — Grado en Ingeniería de Software y
Ciberseguridad, U-tad, curso 2026-2027. Autor: Marcos Villaverde González.

> ⚠️ **Aviso de seguridad.** PhishLens analiza correos potencialmente maliciosos. Úsalo en una
> máquina virtual aislada, no abras nunca los correos de prueba con un cliente de correo y no
> ejecutes sus adjuntos. La herramienta solo los lee como texto y calcula los hashes de los adjuntos.

## Qué hace

Recibe un correo (`.eml`) y devuelve un veredicto (**limpio**, **sospechoso** o **phishing**), una
puntuación de riesgo de 0 a 100, las evidencias que lo justifican y una explicación con la
recomendación para el usuario.

1. **Parser**: cabeceras, cadena `Received` e IP de origen, cuerpo, enlaces (destino real frente a
   texto visible) y adjuntos (solo hash).
2. **Autenticación**: SPF, DKIM y DMARC, con consultas DNS propias o leyendo `Authentication-Results`.
3. **Heurísticas**: dominios que imitan marcas, enlaces engañosos, `Reply-To` sospechosos, acortadores,
   adjuntos peligrosos.
4. **Reputación**: VirusTotal, AbuseIPDB y urlscan.io. Solo consulta; nunca sube URLs ni ficheros.
5. **Saneamiento**: separa el texto oculto, detecta intentos de *prompt injection*, desactiva URLs y
   seudonimiza al destinatario antes de enviar nada a la IA.
6. **Puntuación** determinista del riesgo.
7. **IA**: un modelo local (Ollama) analiza la ingeniería social. Su respuesta se valida contra un
   esquema JSON y listas permitidas.
8. **Combinación**: las reglas deciden y la IA interpreta. La IA solo puede **subir** el veredicto, y
   solo si está muy segura (probabilidad ≥ 85 %); **nunca puede bajarlo**.
9. **Informes** en la terminal, en HTML (escapado, sin enlaces, con CSP) y en JSON con los indicadores.
10. **Vigilancia de buzón** por IMAP: analiza los correos nuevos y les añade una etiqueta con el veredicto.

## Requisitos

- Linux (probado en Kali Linux) con **Python 3.12 o superior** (probado con Python 3.14).
- Opcional, para el análisis con IA: [Ollama](https://ollama.com) con un modelo descargado
  (recomendado `qwen2.5:14b`; probado también `llama3.1:8b`).
- Opcional, para la reputación: claves gratuitas de VirusTotal, AbuseIPDB y urlscan.io.
- Opcional, para vigilar un buzón: una cuenta con IMAP y una **contraseña de aplicación**.

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
IMAP_SERVIDOR=imap.gmail.com        # vigilancia de buzón
IMAP_USUARIO=
IMAP_CONTRASENA=                    # contraseña de aplicación, nunca la contraseña normal
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

### Analizar un correo

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

### Vigilar un buzón

Revisa la bandeja de entrada, analiza los correos que llegan y les añade una etiqueta
(`PhishLens/Phishing`, `PhishLens/Sospechoso` o `PhishLens/Limpio` en Gmail).

```bash
python -m phishlens.buzon --prueba --una-vez --ultimos 3   # analiza los 3 últimos sin tocar el buzón
python -m phishlens.buzon --una-vez                         # una revisión
python -m phishlens.buzon --intervalo 1                     # vigilancia continua cada minuto
python -m phishlens.buzon --intervalo 1 --informe           # y guarda los informes en reports/buzon/
```

Medidas de seguridad de este modo:

- **Solo lee y etiqueta.** Una lista blanca de comandos IMAP impide borrar, mover, copiar o marcar
  como leído cualquier correo, aunque la credencial lo permitiera.
- Descarga con `BODY.PEEK[]`, de modo que **los correos siguen sin leer**.
- En la primera revisión **no analiza los correos que ya había**; solo los que llegan después.
- **Reputación desactivada por defecto** (`--con-reputacion` para activarla): los enlaces del correo
  personal no se envían a servicios externos.
- Usa una **contraseña de aplicación** revocable, guardada solo en `.env`.

Para Gmail: activa la verificación en dos pasos y crea la contraseña de aplicación en
<https://myaccount.google.com/apppasswords>. Se recomienda usar una cuenta de pruebas.

## Resultados

Evaluación con 200 correos reales (100 de phishing de Phishing Pot y 100 legítimos de SpamAssassin),
en un **conjunto de prueba** que no se usó para ajustar la herramienta:

| Configuración | Detección | Falsos positivos | F1 |
|---|---|---|---|
| Solo reglas | 70 % | 0 % | 0,82 |
| **Reglas + IA (`qwen2.5:14b`)** | **89 %** | **0 %** | **0,94** |
| Reglas + IA (`llama3.1:8b`) | 83 % | 2 % | 0,90 |

Seguridad del componente de IA: frente a 16 ataques de *prompt injection*, con las defensas activas el
modelo no fue engañado en ninguno y el veredicto final se mantuvo en los 16 casos.

Los resúmenes completos están en [`docs/resultados/`](docs/resultados/).

## Pruebas

```bash
python -m pytest -q
```

165 pruebas superadas y 1 fallo esperado (homoglifos cirílicos, limitación conocida). No necesitan red
ni modelo de IA: las APIs, el modelo y el servidor IMAP se simulan.

Análisis estático:

```bash
pip install ruff bandit pip-audit
ruff check phishlens/ tests/
bandit -r phishlens/
pip-audit -r requirements.txt
```

### Red team contra la IA

```bash
python -m phishlens.redteam.evaluar
```

### Evaluación con correos reales

```bash
python -m phishlens.evaluacion.preparar                       # conjunto de desarrollo
python -m phishlens.evaluacion.preparar --conjunto prueba     # conjunto de prueba (sin solapamiento)
python -m phishlens.evaluacion.evaluar --conjunto prueba      # con IA (unos 45 minutos)
python -m phishlens.evaluacion.analizar_ia                    # análisis de errores de la IA (desarrollo)
OLLAMA_MODEL=llama3.1:8b python -m phishlens.evaluacion.evaluar --conjunto prueba   # otro modelo
```

Los correos se descargan en `samples/`, que está excluida de Git.

## Limitaciones

- No detecta homoglifos de otros alfabetos en las instrucciones dirigidas a la IA (el veredicto se
  mantiene gracias a la arquitectura, pero el intento no se señala).
- El correo legítimo de la evaluación es de 2002 y está en inglés; falta evaluar con correo actual en español.
- No se ha comparado con modelos comerciales (API de Claude) por su coste.
- La vigilancia de buzón es un prototipo: revisa periódicamente, no filtra en tiempo real, y solo la
  bandeja de entrada.

## Estructura
```
phishlens/
├── main.py            # línea de comandos
├── analisis.py        # orquestación del análisis
├── parser.py          # descomposición del correo
├── checks/            # autenticación y heurísticas
├── enrichment/        # VirusTotal, AbuseIPDB, urlscan.io
├── llm/               # saneamiento, prompt, proveedores y validación de la IA
├── scoring.py         # puntuación de riesgo
├── combinacion.py     # combinación de reglas e IA
├── report.py          # informes HTML y JSON
├── buzon.py           # vigilancia de buzón por IMAP
├── redteam/           # corpus de ataques contra la IA y su evaluación
└── evaluacion/        # corpus de correos reales, métricas y análisis de errores
tests/                 # pruebas automáticas y correos ficticios de prueba
docs/                  # registro de uso de IA y resultados
```

## Uso de IA en el desarrollo

El desarrollo se ha realizado con apoyo de Claude (Anthropic). Todo el uso queda registrado en
[`docs/USO_IA.md`](docs/USO_IA.md).

## Datos de evaluación

- [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) — correos de phishing reales (CC BY-NC 4.0).
- [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) — correo legítimo (*easy_ham*).

Estos correos no se incluyen en el repositorio; se descargan con `phishlens.evaluacion.preparar`.
