"""
Análisis de los errores de la IA a partir de los resultados guardados (hito H8b).

No vuelve a llamar al modelo: lee las respuestas que el evaluador guardó en
samples/<conjunto>/resultados_<modelo>.jsonl y simula cómo cambiarían las
métricas del sistema completo con distintas reglas de combinación. Así se
pueden probar muchas variantes en segundos.

Se trabaja SOLO con el conjunto de desarrollo: el de prueba se reserva para la
medición final, para no ajustar el sistema mirando las cifras que se publican.

Uso:
    python -m phishlens.evaluacion.analizar_ia
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
CARPETAS = {"desarrollo": RAIZ / "samples" / "evaluacion", "prueba": RAIZ / "samples" / "evaluacion_prueba"}

# Tácticas que implican pedir algo a la víctima: el núcleo de un ataque de phishing
TACTICAS_DE_PETICION = {"peticion_credenciales", "peticion_pago", "peticion_secreto"}


def cargar(carpeta: Path) -> list[dict]:
    """Carga los resultados con IA. Si un correo aparece varias veces (reintentos), vale la última."""
    ficheros = sorted(p for p in carpeta.glob("resultados_*.jsonl") if "reglas" not in p.name)
    if not ficheros:
        raise SystemExit(f"No hay resultados con IA en {carpeta}")
    por_correo = {}
    for linea in ficheros[-1].read_text(encoding="utf-8").splitlines():
        if linea.strip():
            datos = json.loads(linea)
            por_correo[datos["sha256"]] = datos
    return list(por_correo.values())


def metricas(resultados: list[dict], detecta) -> dict:
    """detecta(r) -> True/False: si el sistema marca el correo como sospechoso o phishing."""
    vp = fp = vn = fn = 0
    for r in resultados:
        real, pred = r["etiqueta"] == "phishing", detecta(r)
        vp += real and pred
        fn += real and not pred
        fp += (not real) and pred
        vn += (not real) and not pred
    det = vp / (vp + fn) if vp + fn else 0.0
    tfp = fp / (fp + vn) if fp + vn else 0.0
    prec = vp / (vp + fp) if vp + fp else 0.0
    f1 = 2 * prec * det / (prec + det) if prec + det else 0.0
    return {"vp": vp, "fp": fp, "vn": vn, "fn": fn, "deteccion": det, "fp_tasa": tfp, "f1": f1}


def reglas_detectan(r: dict) -> bool:
    return r["veredicto_reglas"] != "limpio"


def sistema(umbral: float, campo: str = "prob_ia_con_datos", condicion=None):
    """
    Simula combinacion.py: la IA puede subir el veredicto (nunca bajarlo).
    El correo queda detectado si lo detectan las reglas o si la IA supera el umbral
    (y, opcionalmente, cumple una condición extra de coherencia).
    """
    def detecta(r):
        if reglas_detectan(r):
            return True
        p = r.get(campo)
        if p is None or p < umbral:
            return False
        return condicion(r) if condicion else True
    return detecta


def con_peticion(r: dict) -> bool:
    """La IA solo puede subir el veredicto si identifica una petición a la víctima."""
    return bool(TACTICAS_DE_PETICION & set(r.get("tacticas") or []))


def fila(nombre, m):
    return (f"| {nombre} | {m['deteccion']:.1%} | {m['fp_tasa']:.1%} | {m['f1']:.2f} | "
            f"{m['vp']}/{m['fp']}/{m['vn']}/{m['fn']} |")


def main() -> int:
    args = argparse.ArgumentParser(description="Analiza los errores de la IA (H8b)")
    args.add_argument("--conjunto", choices=["desarrollo", "prueba"], default="desarrollo")
    conjunto = args.parse_args().conjunto
    if conjunto == "prueba":
        print("AVISO: el conjunto de prueba solo debe usarse para la medición final, no para ajustar.\n")
    res = cargar(CARPETAS[conjunto])
    legit = [r for r in res if r["etiqueta"] == "legitimo"]
    phish = [r for r in res if r["etiqueta"] == "phishing"]
    salida = [f"# Análisis de la IA (H8b) — conjunto de {conjunto}", "",
              f"Correos: {len(res)} ({len(phish)} phishing, {len(legit)} legítimos). "
              f"Sin respuesta de la IA: {sum(1 for r in res if r.get('prob_ia_con_datos') is None)}.", ""]

    # 1. Qué probabilidades da la IA a cada tipo de correo
    salida += ["## 1. Probabilidades que da la IA (con datos técnicos)", "",
               "| Probabilidad | Legítimos | Phishing |", "|---|---|---|"]
    cl = Counter(r.get("prob_ia_con_datos") for r in legit)
    cp = Counter(r.get("prob_ia_con_datos") for r in phish)
    for p in sorted({*cl, *cp}, key=lambda x: (x is None, x)):
        salida.append(f"| {'sin respuesta' if p is None else f'{p:.0%}'} | {cl.get(p, 0)} | {cp.get(p, 0)} |")

    # 2. Barrido de umbrales
    salida += ["", "## 2. Sistema completo según el umbral de la IA", "",
               "| Variante | Detección | Falsos positivos | F1 | VP/FP/VN/FN |", "|---|---|---|---|---|",
               fila("Solo reglas", metricas(res, reglas_detectan))]
    for u in (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95):
        marca = " (actual)" if u == 0.7 else ""
        salida.append(fila(f"IA con datos, umbral {u:.0%}{marca}", metricas(res, sistema(u))))
    for u in (0.7, 0.8, 0.9):
        salida.append(fila(f"IA sola, umbral {u:.0%}", metricas(res, sistema(u, "prob_ia_sola"))))

    # 3. Coherencia: la IA solo sube si identifica una petición a la víctima
    salida += ["", "## 3. Exigiendo que la IA identifique una petición a la víctima", "",
               "| Variante | Detección | Falsos positivos | F1 | VP/FP/VN/FN |", "|---|---|---|---|---|"]
    for u in (0.7, 0.8, 0.9):
        salida.append(fila(f"IA con datos, umbral {u:.0%} + petición", metricas(res, sistema(u, condicion=con_peticion))))

    # 4. Qué dice la IA de los legítimos que marca (umbral actual, sin que las reglas los detecten)
    fps = [r for r in legit if not reglas_detectan(r) and (r.get("prob_ia_con_datos") or 0) >= 0.7]
    vps = [r for r in phish if not reglas_detectan(r) and (r.get("prob_ia_con_datos") or 0) >= 0.7]
    salida += ["", f"## 4. Falsos positivos causados por la IA (umbral actual): {len(fps)}", "",
               "| | Falsos positivos de la IA | Phishing que solo detecta la IA |", "|---|---|---|"]
    tf, tv = Counter(r.get("tipo_fraude") or "-" for r in fps), Counter(r.get("tipo_fraude") or "-" for r in vps)
    for t in sorted({*tf, *tv}):
        salida.append(f"| Tipo: {t} | {tf.get(t, 0)} | {tv.get(t, 0)} |")
    af = Counter(a for r in fps for a in (r.get("tacticas") or []))
    av = Counter(a for r in vps for a in (r.get("tacticas") or []))
    for a in sorted({*af, *av}):
        salida.append(f"| Táctica: {a} | {af.get(a, 0)} | {av.get(a, 0)} |")

    texto = "\n".join(salida) + "\n"
    print(texto)
    destino = RAIZ / "docs" / "resultados" / f"analisis_ia_{conjunto}.md"
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(texto, encoding="utf-8")
    print(f"Guardado en {destino.relative_to(RAIZ)}")

    # Para revisarlo en pantalla (no se guarda: puede citar contenido de los correos)
    print("\nEjemplos de explicaciones de la IA en falsos positivos (solo en pantalla):")
    for r in fps[:8]:
        print(f"- {Path(r['fichero']).name} [{r.get('prob_ia_con_datos')}, {r.get('tipo_fraude')}]: "
              f"{(r.get('explicacion') or '')[:160]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
