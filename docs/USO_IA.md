# Registro de uso de IA en el desarrollo

| Fecha | Herramienta | Tarea | Qué generó la IA | Revisión / cambios realizados |
|---|---|---|---|---|
| 2026-09-23 | Claude (claude.ai) | Elección del proyecto, análisis de herramientas similares y estructura inicial | Propuesta de estructura de carpetas, requirements.txt y .gitignore | Revisado y ejecutado manualmente en la VM Kali |
| 2026-09-23 | Claude (claude.ai) | Hito 1: módulo de parseo | parser.py, main.py, correo de prueba y tests | Ejecutado en la VM, 5 tests superados; revisado el código línea a línea |
| 2026-09-23 | Claude (claude.ai) | Hito 2: comprobaciones deterministas | modelos.py, autenticacion.py, heuristicas.py, tests de checks | 24 tests superados; ajustada la detección de dominios para evitar falsos positivos (correosexpress.com, applebees.com) |
| 2026-09-23 | Claude (claude.ai) | Hito 3: puntuación de riesgo | scoring.py, correo legítimo de prueba, tests de puntuación | 29 tests superados; revisados los umbrales y la regla de hallazgo crítico |
| 2026-09-23 | Claude (claude.ai) | Hito 4: enriquecimiento | config.py, clientes de VirusTotal/AbuseIPDB/urlscan, caché, limitador de cuota y tests | 40 tests superados; decidido solo consultar (nunca subir) indicadores |
| 2026-09-24 | Claude (claude.ai) | Hito 5 (parte 1): preparación para la IA | saneamiento.py, prompt.py, esquema.py y tests | 55 tests superados; revisadas las defensas contra prompt injection |
| 2026-09-24 | Claude (claude.ai) | Hito 5 (parte 2): conexión con el modelo | proveedores.py, analizador.py, combinacion.py, main.py con escape() y tests | 68 tests superados; probado con qwen2.5:14b en Ollama local |
| 2026-09-24 | Claude (claude.ai) | Hito 5 (parte 3): correcciones tras prueba real | probabilidad_phishing en lugar de confianza ambigua, coherencia MITRE con evidencias, prompt sobre hallazgos de inyección | 72 tests superados; errores detectados al revisar la salida real de qwen2.5:14b |
| 2026-09-28 | Claude (claude.ai) | Hito 6 (parte 1): red team automatizado | corpus de 16 ataques, tests de detección/filtrado/arquitectura, refuerzo del saneamiento | 115 tests + 1 xfail (homoglifos, limitación conocida); el red team destapó 5 huecos (remitente, adjunto, comentarios HTML, JSON falso, caracteres invisibles), ya corregidos |
| 2026-09-28 | Claude (claude.ai) | Hito 6 (parte 2): evaluación de ataques contra el modelo real | evaluar.py (modos ingenuo/defensas), tests del evaluador | Ejecutado contra qwen2.5:14b; resultados en docs/resultados/ |
