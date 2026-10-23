#!/usr/bin/env python3
"""
Author: Ing. Ivan Omonte C.
"""

import os
import re
import csv
import sys
from datetime import date
from collections import Counter

import shodan

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

API_KEY = os.environ.get("SHODAN_API_KEY", "")
QUERY = 'country:BO "X-Powered-By: PHP"'
CSV_OUT = "php_bolivia_vulnerables.csv"

ROJO = "#D7263D"
AZUL = "#1B4965"
VERDE = "#2A9D8F"
GRIS = "#8A8D91"
FONDO = "#FFFFFF"
AMARILLO = "#FFD166"

CVES = "CVE-2026-109618 / CVE-2026-109619"
FECHA = date.today().strftime("%d/%m/%Y")
FOOTER = "Fuente: Shodan  |  {}  |  {}".format(CVES, FECHA)

PATCHED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")


def es_vulnerable(major, minor, patch):
    if major < 8:
        return True
    if major == 8 and minor <= 1:
        return True
    umbral = PATCHED.get((major, minor))
    if umbral is None:
        return False
    return patch < umbral


# Graficos
def _footer(fig):
    fig.text(0.5, 0.012, FOOTER, ha="center", va="bottom",
             fontsize=9, color=GRIS)


def _top_lineas(counter, k=5, ancho=22):
    lineas = []
    for i, (nombre, v) in enumerate(counter.most_common(k), 1):
        corto = nombre if len(nombre) <= ancho else nombre[:ancho - 1] + "…"
        lineas.append("{}. {} — {}".format(i, corto, v))
    return lineas


def grafico_barh(counter, titulo, archivo, color):
    """Barras horizontales con TODAS las categorias, etiquetas de valor."""
    items = counter.most_common()
    if not items:
        print("  (sin datos para {})".format(archivo))
        return
    etiquetas = [k for k, _ in items][::-1]
    valores = [v for _, v in items][::-1]

    altura = max(4.5, 0.42 * len(items) + 2.4)
    fig, ax = plt.subplots(figsize=(10.8, altura), dpi=100)
    fig.patch.set_facecolor(FONDO)
    ax.set_facecolor(FONDO)

    barras = ax.barh(etiquetas, valores, color=color)
    maxv = max(valores)
    for b, v in zip(barras, valores):
        ax.text(b.get_width() + maxv * 0.01, b.get_y() + b.get_height() / 2,
                str(v), va="center", ha="left", fontsize=10, color="#333")

    ax.set_title(titulo, fontsize=17, fontweight="bold", color=AZUL, pad=16,
                 loc="left")
    ax.set_xlim(0, maxv * 1.12)
    ax.tick_params(axis="y", labelsize=10)
    ax.tick_params(axis="x", labelsize=9, colors=GRIS)
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    ax.spines["left"].set_color(GRIS)
    ax.spines["bottom"].set_color(GRIS)

    fig.subplots_adjust(left=0.30, right=0.97, top=0.92, bottom=0.07 + 0.6 / altura)
    _footer(fig)
    fig.savefig(archivo, facecolor=FONDO)
    plt.close(fig)
    print("  guardado: {}".format(archivo))


def grafico_lista_empresas(counter, archivo):
    """Ranking: TODAS las empresas ordenadas, con numero, conteo y %."""
    items = counter.most_common()
    if not items:
        print("  (sin datos para {})".format(archivo))
        return
    n = len(items)
    total = sum(v for _, v in items)
    altura = max(5.0, 0.40 * n + 2.2)

    fig, ax = plt.subplots(figsize=(10.8, altura), dpi=100)
    fig.patch.set_facecolor(FONDO)
    ax.set_facecolor(FONDO)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, n)
    ax.invert_yaxis()
    ax.axis("off")

    for i, (nombre, v) in enumerate(items):
        if i % 2 == 0:
            ax.axhspan(i, i + 1, color="#F2F4F7", zorder=0)
        y = i + 0.5
        corto = nombre if len(nombre) <= 48 else nombre[:47] + "…"
        pct = 100.0 * v / total
        ax.text(0.015, y, str(i + 1), va="center", ha="left",
                fontsize=10, fontweight="bold", color=GRIS)
        ax.text(0.060, y, corto, va="center", ha="left",
                fontsize=11, color="#222")
        ax.text(0.985, y, "{}  ({:.1f}%)".format(v, pct), va="center",
                ha="right", fontsize=11, fontweight="bold", color=AZUL)

    ax.set_title("Organizaciones / ISP con hosts PHP vulnerables (ordenadas)",
                 fontsize=16, fontweight="bold", color=AZUL, loc="left", pad=14)
    fig.subplots_adjust(left=0.02, right=0.98, top=0.95, bottom=0.05)
    _footer(fig)
    fig.savefig(archivo, facecolor=FONDO)
    plt.close(fig)
    print("  guardado: {}".format(archivo))


def grafico_resumen(total, por_org, por_ciudad, archivo):
    """Banner cuadrado (1080x1080) con total + Top 5 de org y ciudad/municipio."""
    n_orgs = len(por_org)
    n_ciu = len(por_ciudad)

    fig = plt.figure(figsize=(10.8, 10.8), dpi=100)
    fig.patch.set_facecolor(AZUL)

    fig.text(0.5, 0.945, "SERVIDORES PHP EXPUESTOS EN BOLIVIA",
             ha="center", fontsize=20, fontweight="bold", color="#FFFFFF")
    fig.text(0.5, 0.905, "potencialmente vulnerables a RCE critico (CVSS 9.2)",
             ha="center", fontsize=12.5, color="#CBD5E1")

    fig.text(0.5, 0.78, str(total), ha="center", fontsize=86,
             fontweight="bold", color=ROJO)
    fig.text(0.5, 0.70, "hosts con version sin parchear detectada",
             ha="center", fontsize=13.5, color="#FFFFFF")
    fig.text(0.5, 0.655,
             "{} organizaciones  ·  {} ciudades/municipios".format(n_orgs, n_ciu),
             ha="center", fontsize=12.5, color="#CBD5E1")

    # top 5 organizaciones
    fig.text(0.07, 0.55, "Top 5 organizaciones", ha="left",
             fontsize=14, fontweight="bold", color=AMARILLO)
    y = 0.50
    for linea in _top_lineas(por_org):
        fig.text(0.07, y, linea, ha="left", fontsize=12, color="#FFFFFF")
        y -= 0.045

    # top 5 ciudades/municipios
    fig.text(0.55, 0.55, "Top 5 ciudades/municipios", ha="left",
             fontsize=14, fontweight="bold", color=AMARILLO)
    y = 0.50
    for linea in _top_lineas(por_ciudad):
        fig.text(0.55, y, linea, ha="left", fontsize=12, color="#FFFFFF")
        y -= 0.045

    fig.text(0.5, 0.045, FOOTER, ha="center", fontsize=10, color="#9FB3C8")
    fig.savefig(archivo, facecolor=fig.get_facecolor())
    plt.close(fig)
    print("  guardado: {}".format(archivo))

def main():
    if not API_KEY:
        sys.exit("Falta la API key.")

    api = shodan.Shodan(API_KEY)

    filas = []
    por_org = Counter()
    por_ciudad = Counter()
    por_version = Counter()

    print("Buscando: {}\n".format(QUERY))

    try:
        for match in api.search_cursor(QUERY):
            banner = match.get("data", "") or ""
            m = VERSION_RE.search(banner)
            if not m:
                continue

            major, minor, patch = (int(x) for x in m.groups())
            if not es_vulnerable(major, minor, patch):
                continue

            version = "{}.{}.{}".format(major, minor, patch)
            rama = "{}.{}".format(major, minor)
            loc = match.get("location", {}) or {}

            fila = {
                "ip": match.get("ip_str", ""),
                "puerto": match.get("port", ""),
                "version": version,
                "org": match.get("org") or "Desconocido",
                "asn": match.get("asn") or "N/A",
                "ciudad": loc.get("city") or "Desconocida",
            }
            filas.append(fila)
            por_org[fila["org"]] += 1
            por_ciudad[fila["ciudad"]] += 1
            por_version[rama] += 1

    except shodan.APIError as e:
        print("Error de API de Shodan: {}".format(e))
        if not filas:
            return

    campos = ["ip", "puerto", "version", "org", "asn", "ciudad"]
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)

    total = len(filas)
    print("Total de hosts vulnerables encontrados: {}".format(total))
    print("Detalle exportado a: {}\n".format(CSV_OUT))

    print("== Organizaciones ({}) ==".format(len(por_org)))
    for org, n in por_org.most_common():
        print("  {:>4}  {}".format(n, org))

    print("\n== Ciudades/Municipios ({}) ==".format(len(por_ciudad)))
    for ciudad, n in por_ciudad.most_common():
        print("  {:>4}  {}".format(n, ciudad))

    print("\n== Versiones PHP (rama) ==")
    for rama, n in por_version.most_common():
        print("  {:>4}  PHP {}".format(n, rama))

    print("\nGenerando graficos...")
    if total == 0:
        print("  Sin datos: no se generan imagenes.")
        return

    grafico_resumen(total, por_org, por_ciudad, "grafico_resumen.png")
    grafico_lista_empresas(por_org, "grafico_lista_organizaciones.png")
    grafico_barh(por_org,
                 "Hosts PHP vulnerables por organizacion / ISP",
                 "grafico_organizaciones.png", AZUL)
    grafico_barh(por_ciudad,
                 "Hosts PHP vulnerables por ciudad/municipio",
                 "grafico_ciudades.png", ROJO)
    grafico_barh(por_version,
                 "Hosts PHP vulnerables por version (rama)",
                 "grafico_versiones.png", VERDE)

    print("\nListo. Imagenes en la carpeta actual.")


if __name__ == "__main__":
    main()