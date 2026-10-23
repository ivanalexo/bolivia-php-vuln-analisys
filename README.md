# Overview
Escaneo pasivo de servidores PHP expuestos en Bolivia (Shodan) + graficos.

Detecta candidatos vulnerables a CVE-2026-109618 / CVE-2026-109619 comparando
la version reportada contra los parches oficiales (8.5.12, 8.4.27, 8.3.36, 8.2.35; ramas <= 8.1 / 5.x / 7.x siempre vulnerables).

Genera:
  - php_bolivia_vulnerables.csv          (detalle: ip, puerto, version, org, asn, ciudad)
  - grafico_resumen.png                  (banner: total, CVEs, fecha, Top 5 org y ciudad/municipio)
  - grafico_lista_organizaciones.png     (TODAS las empresas ordenadas, con % )
  - grafico_organizaciones.png           (barras: TODAS las organizaciones/ISP)
  - grafico_ciudades.png                 (barras: TODAS las ciudades/municipios)
  - grafico_versiones.png                (distribucion por version de PHP)

# Requisitos
    - python >= v3.9
    - pip install shodan matplotlib

# Ejecución
`$ python php_bolivia_shodan.py`

# Descargo de reponsabilidad
Esta publicación tiene fines exclusivamente informativos y de concientización en seguridad. Los datos provienen de fuentes públicas (motor de búsqueda Shodan) y reflejan una medición pasiva: en ningún momento se accedió, vulneró ni interactuó con los sistemas analizados. El objetivo es promover la actualización y buenas prácticas, no señalar ni perjudicar a ninguna entidad