# Cambios respecto a la memoria de planteamiento (entregada)

Pendiente de reflejar en la memoria final (hito 9).

## Hardware y entorno
- La GPU es una RTX 4080 Laptop de 12 GB (ya corregido antes de la entrega).
- Ollama escucha solo en 127.0.0.1 del anfitrión; la VM accede por NAT de VirtualBox (10.0.2.2), sin exponer el servicio a la red (ya corregido antes de la entrega).

## Diseño
- Modelo elegido: qwen2.5:14b (contexto de 4.096 tokens por el límite de memoria de la GPU).
- El esquema de respuesta usa "probabilidad_phishing" (0-1) en lugar de "es_phishing" + "confianza", que resultaba ambiguo.
- Las técnicas MITRE se validan contra las evidencias del correo (por ejemplo, T1566.001 solo si hay un adjunto sospechoso).
- Los hallazgos del saneamiento (TEXTO_OCULTO, POSIBLE_PROMPT_INJECTION) también suman en la puntuación: añadir la flecha "Saneamiento -> Puntuación" en el diagrama de flujo.
- La salida por terminal escapa todo el texto del correo y de la IA (inyección de marcado en la terminal).

## Resultados del red team (hito 6)
- 16 ataques; el red team destapó 5 huecos en el saneamiento, ya corregidos.
- Limitación conocida: homoglifos cirílicos (A16) no se detectan por patrones.
- qwen2.5:14b engañado en 2/16 ataques sin defensas y en 0/16 con defensas; el veredicto final resiste en 16/16.
- Matiz: el modo con defensas también pasa al modelo el veredicto de las reglas, lo que ancla su opinión (pendiente de ablación en el hito 8).

## Estado
- Hitos H0 a H6 completados.
