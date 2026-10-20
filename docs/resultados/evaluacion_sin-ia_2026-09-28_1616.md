# Evaluación de PhishLens con correos reales

- Fecha: 2026-09-28 16:16
- Modelo de IA: no usado
- Correos: 200 (100 de phishing, 100 legítimos)
- Fuentes: phishing_pot (100), spamassassin_easy_ham (100)
- Modo: sin red (autenticación según las cabeceras del propio correo, sin reputación)

## Métricas

| Configuración | n | Exactitud | Detección | Falsos positivos | Precisión | F1 | VP/FP/VN/FN |
|---|---|---|---|---|---|---|---|
| Reglas (sospechoso o phishing) | 200 | 62.5% | 79.0% | 54.0% | 59.4% | 0.68 | 79/54/46/21 |
| Reglas (solo phishing) | 200 | 65.5% | 31.0% | 0.0% | 100.0% | 0.47 | 31/0/100/69 |

Detección = phishing detectado / total de phishing. Falsos positivos = legítimos marcados / total de legítimos.

## Hallazgos que provocan falsos positivos (reglas)

- DKIM_AUSENTE: 54
- SPF_SIN_VALIDAR: 54
- RETURN_PATH_DISTINTO: 51
- URL_SIN_HTTPS: 48
- REPLY_TO_DISTINTO: 25
- POSIBLE_PROMPT_INJECTION: 1

## Hallazgos más frecuentes en el phishing

- DKIM_AUSENTE: 54
- RETURN_PATH_DISTINTO: 46
- SPF_SIN_VALIDAR: 39
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
- phishing/phishing_pot-sample-1764.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-2941.eml (puntuación 15; SPF_SOFTFAIL)
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
