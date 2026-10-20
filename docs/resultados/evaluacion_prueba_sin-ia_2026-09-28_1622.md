# Evaluación de PhishLens con correos reales

- Fecha: 2026-09-28 16:22
- Conjunto: prueba
- Modelo de IA: no usado
- Correos: 200 (100 de phishing, 100 legítimos)
- Fuentes: phishing_pot (100), spamassassin_easy_ham (100)
- Modo: sin red (autenticación según las cabeceras del propio correo, sin reputación)

## Métricas

| Configuración | n | Exactitud | Detección | Falsos positivos | Precisión | F1 | VP/FP/VN/FN |
|---|---|---|---|---|---|---|---|
| Reglas (sospechoso o phishing) | 200 | 85.0% | 70.0% | 0.0% | 100.0% | 0.82 | 70/0/100/30 |
| Reglas (solo phishing) | 200 | 65.5% | 31.0% | 0.0% | 100.0% | 0.47 | 31/0/100/69 |

Detección = phishing detectado / total de phishing. Falsos positivos = legítimos marcados / total de legítimos.

## Hallazgos que provocan falsos positivos (reglas)

- ninguno

## Hallazgos más frecuentes en el phishing

- DKIM_AUSENTE: 59
- RETURN_PATH_DISTINTO: 43
- URL_SIN_HTTPS: 37
- TEXTO_OCULTO: 34
- SPF_SIN_VALIDAR: 32
- URL_ACORTADA: 19
- REPLY_TO_DISTINTO: 15
- SPF_FAIL: 13
- URL_TEXTO_ENGANOSO: 11
- DKIM_FAIL: 9

## Phishing no detectado por las reglas

- phishing/phishing_pot-sample-652.eml (puntuación 5; DKIM_AUSENTE)
- phishing/phishing_pot-sample-112.eml (puntuación 5; DKIM_AUSENTE)
- phishing/phishing_pot-sample-3267.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-1467.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-628.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-2476.eml (puntuación 15; DKIM_AUSENTE, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-3484.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-2836.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-3125.eml (puntuación 5; DKIM_AUSENTE)
- phishing/phishing_pot-sample-1344.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-1569.eml (puntuación 20; DKIM_AUSENTE, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR, URL_SIN_HTTPS)
- phishing/phishing_pot-sample-3899.eml (puntuación 5; URL_SIN_HTTPS)
- phishing/phishing_pot-sample-735.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-593.eml (puntuación 5; URL_SIN_HTTPS)
- phishing/phishing_pot-sample-3431.eml (puntuación 15; TEXTO_OCULTO)
- phishing/phishing_pot-sample-560.eml (puntuación 15; URL_ACORTADA)
- phishing/phishing_pot-sample-4022.eml (puntuación 15; DKIM_AUSENTE, SPF_SIN_VALIDAR, URL_SIN_HTTPS)
- phishing/phishing_pot-sample-952.eml (puntuación 10; DKIM_AUSENTE, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-739.eml (puntuación 5; URL_SIN_HTTPS)
- phishing/phishing_pot-sample-232.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-992.eml (puntuación 10; DKIM_AUSENTE, SPF_SIN_VALIDAR)
- phishing/phishing_pot-sample-114.eml (puntuación 5; REPLY_TO_DISTINTO)
- phishing/phishing_pot-sample-233.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-44.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-3045.eml (puntuación 5; DKIM_AUSENTE)
- phishing/phishing_pot-sample-2340.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-3912.eml (puntuación 15; URL_ACORTADA)
- phishing/phishing_pot-sample-2204.eml (puntuación 0; sin hallazgos)
- phishing/phishing_pot-sample-1969.eml (puntuación 5; RETURN_PATH_DISTINTO)
- phishing/phishing_pot-sample-208.eml (puntuación 15; DKIM_AUSENTE, RETURN_PATH_DISTINTO, SPF_SIN_VALIDAR)
