# Análisis de la IA (H8b) — conjunto de desarrollo

Correos: 200 (100 phishing, 100 legítimos). Sin respuesta de la IA: 3.

## 1. Probabilidades que da la IA (con datos técnicos)

| Probabilidad | Legítimos | Phishing |
|---|---|---|
| 0% | 2 | 0 |
| 5% | 2 | 0 |
| 10% | 12 | 0 |
| 20% | 30 | 0 |
| 30% | 12 | 0 |
| 60% | 1 | 0 |
| 70% | 26 | 0 |
| 80% | 15 | 28 |
| 85% | 0 | 9 |
| 90% | 0 | 48 |
| 95% | 0 | 10 |
| 100% | 0 | 2 |
| sin respuesta | 0 | 3 |

## 2. Sistema completo según el umbral de la IA

| Variante | Detección | Falsos positivos | F1 | VP/FP/VN/FN |
|---|---|---|---|---|
| Solo reglas | 77.0% | 1.0% | 0.87 | 77/1/99/23 |
| IA con datos, umbral 50% | 100.0% | 42.0% | 0.83 | 100/42/58/0 |
| IA con datos, umbral 60% | 100.0% | 42.0% | 0.83 | 100/42/58/0 |
| IA con datos, umbral 70% (actual) | 100.0% | 41.0% | 0.83 | 100/41/59/0 |
| IA con datos, umbral 80% | 100.0% | 16.0% | 0.93 | 100/16/84/0 |
| IA con datos, umbral 85% | 89.0% | 1.0% | 0.94 | 89/1/99/11 |
| IA con datos, umbral 90% | 89.0% | 1.0% | 0.94 | 89/1/99/11 |
| IA con datos, umbral 95% | 78.0% | 1.0% | 0.87 | 78/1/99/22 |
| IA sola, umbral 70% | 100.0% | 27.0% | 0.88 | 100/27/73/0 |
| IA sola, umbral 80% | 100.0% | 20.0% | 0.91 | 100/20/80/0 |
| IA sola, umbral 90% | 94.0% | 2.0% | 0.96 | 94/2/98/6 |

## 3. Exigiendo que la IA identifique una petición a la víctima

| Variante | Detección | Falsos positivos | F1 | VP/FP/VN/FN |
|---|---|---|---|---|
| IA con datos, umbral 70% + petición | 87.0% | 3.0% | 0.92 | 87/3/97/13 |
| IA con datos, umbral 80% + petición | 87.0% | 2.0% | 0.92 | 87/2/98/13 |
| IA con datos, umbral 90% + petición | 86.0% | 1.0% | 0.92 | 86/1/99/14 |

## 4. Falsos positivos causados por la IA (umbral actual): 40

| | Falsos positivos de la IA | Phishing que solo detecta la IA |
|---|---|---|
| Tipo: extorsion | 0 | 1 |
| Tipo: malware | 1 | 0 |
| Tipo: otro | 27 | 2 |
| Tipo: robo_credenciales | 9 | 20 |
| Tipo: spam_comercial | 3 | 0 |
| Táctica: autoridad | 4 | 9 |
| Táctica: curiosidad | 15 | 7 |
| Táctica: miedo | 23 | 11 |
| Táctica: peticion_credenciales | 2 | 9 |
| Táctica: peticion_pago | 0 | 1 |
| Táctica: recompensa | 5 | 6 |
| Táctica: suplantacion_marca | 34 | 10 |
| Táctica: urgencia | 10 | 16 |
