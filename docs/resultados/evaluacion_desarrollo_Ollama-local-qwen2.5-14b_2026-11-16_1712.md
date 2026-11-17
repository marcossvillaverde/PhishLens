# Evaluación de PhishLens con correos reales

- Fecha: 2026-11-16 17:12
- Conjunto: desarrollo
- Modelo de IA: Ollama local (qwen2.5:14b)
- Correos: 200 (100 de phishing, 100 legítimos)
- Fuentes: phishing_pot (100), spamassassin_easy_ham (100)
- Modo: sin red (autenticación según las cabeceras del propio correo, sin reputación)

## Métricas

| Configuración | n | Exactitud | Detección | Falsos positivos | Precisión | F1 | VP/FP/VN/FN |
|---|---|---|---|---|---|---|---|
| Reglas (sospechoso o phishing) | 200 | 88.0% | 77.0% | 1.0% | 98.7% | 0.87 | 77/1/99/23 |
| Reglas (solo phishing) | 200 | 65.5% | 31.0% | 0.0% | 100.0% | 0.47 | 31/0/100/69 |
| Sistema completo: reglas + IA | 200 | 79.5% | 100.0% | 41.0% | 70.9% | 0.83 | 100/41/59/0 |
| IA con datos técnicos (≥ 50 %) | 197 | 78.7% | 100.0% | 42.0% | 69.8% | 0.82 | 97/42/58/0 |
| IA sola, solo contenido (≥ 50 %) | 198 | 86.9% | 100.0% | 26.0% | 79.0% | 0.88 | 98/26/74/0 |

Detección = phishing detectado / total de phishing. Falsos positivos = legítimos marcados / total de legítimos.

## Hallazgos que provocan falsos positivos (reglas)

- POSIBLE_PROMPT_INJECTION: 1
- RETURN_PATH_DISTINTO: 1

## Hallazgos más frecuentes en el phishing

- DKIM_AUSENTE: 54
- RETURN_PATH_DISTINTO: 46
- SPF_SIN_VALIDAR: 38
- TEXTO_OCULTO: 34
- URL_SIN_HTTPS: 34
- URL_ACORTADA: 24
- DKIM_FAIL: 20
- REPLY_TO_DISTINTO: 19
- DMARC_FAIL: 14
- SPF_FAIL: 9

## Phishing no detectado por las reglas

- phishing/phishing_pot-sample-713.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-245.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-768.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-218.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-1629.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-3437.eml (puntuación 15; TEXTO_OCULTO)
- phishing/phishing_pot-sample-4828.eml (puntuación 15; DKIM_AUSENTE, SPF_SIN_VALIDAR, URL_SIN_HTTPS)
- phishing/phishing_pot-sample-2279.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-2788.eml (puntuación 20; DKIM_AUSENTE, REPLY_TO_DISTINTO, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-1764.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-2941.eml (puntuación 15; SPF_SOFTFAIL)
- phishing/phishing_pot-sample-2818.eml (puntuación 20; DKIM_AUSENTE, REPLY_TO_DISTINTO, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-4946.eml (puntuación 10; DKIM_AUSENTE, URL_SIN_HTTPS)
- phishing/phishing_pot-sample-4393.eml (puntuación 10; DKIM_AUSENTE, URL_SIN_HTTPS)
- phishing/phishing_pot-sample-4730.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-376.eml (puntuación 5; DKIM_AUSENTE)
- phishing/phishing_pot-sample-2212.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-459.eml (puntuación 10; DKIM_AUSENTE, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-2585.eml (puntuación 15; DKIM_AUSENTE, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-543.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-1729.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-3242.eml (puntuación 15; TEXTO_OCULTO)
- phishing/phishing_pot-sample-4599.eml (puntuación 0; sin hallazgos)
