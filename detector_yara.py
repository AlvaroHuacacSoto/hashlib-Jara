import yara
import os
import time
import zipfile
import tempfile
from loguru import logger
logger.remove()
logger.add(lambda _: None)
from androguard.core.apk import APK

DIR = "/home/alim/exposicion final"
ARCHIVOS = ["CairosOriginal.apk", "CairosVenom.apk", "payload.apk"]

REGLAS_DEX = yara.compile(source="""
    rule dex_metasploit_payload {
        meta:
            description = "Detecta payload de Metasploit en DEX"
            author = "Lab Seguridad"
            severity = "critical"

        strings:
            $a = "Ljava/lang/reflect/Method;"
            $b = "Ljava/net/URLConnection;"
            $c = "addRequestProperty"
            $d = ";->startService(Landroid/content/Context;)V"
            $e = ";->openConnection()Ljava/net/URLConnection;"

        condition:
            uint32(0) == 0x0A786564 and
            4 of them
    }

    rule dex_payload_backdoor {
        meta:
            description = "Detecta estructura tipica de RAT/backdoor Android"
            severity = "high"

        strings:
            $ref = "Ljava/lang/reflect/Method;"
            $start = ";->startService(Landroid/content/Context;)V"

        condition:
            uint32(0) == 0x0A786564 and
            all of them
    }
""")

PERMISOS_PELIGROSOS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.SET_WALLPAPER",
    "android.permission.WRITE_SETTINGS",
]


def analizar_apk(ruta, nombre):
    print(f"\n{'=' * 60}")
    print(f"  ANALISIS: {nombre}")
    print(f"{'=' * 60}")

    tamano = os.path.getsize(ruta)
    print(f"  Tamano: {tamano:,} bytes")

    detecciones = []
    puntuacion = 0

    apk = APK(ruta)
    permisos = apk.get_permissions()
    print(f"  Permisos totales: {len(permisos)}")

    peligrosos = [p for p in permisos if p in PERMISOS_PELIGROSOS]
    if len(peligrosos) >= 3:
        print(f"  Permisos peligrosos: {len(peligrosos)}")
        for p in peligrosos:
            print(f"    - {p}")
        puntuacion += len(peligrosos)
        detecciones.append("EXCESO_DE_PERMISOS")

    services = apk.get_services()
    receivers = apk.get_receivers()
    paquetes = set()

    for s in services:
        partes = s.split(".")
        if len(partes) >= 4:
            paquetes.add(".".join(partes[:-1]))

    for r in receivers:
        partes = r.split(".")
        if len(partes) >= 4:
            paquetes.add(".".join(partes[:-1]))

    main_package = apk.get_package()

    subpaquetes_inusuales = [
        p for p in paquetes
        if p.startswith(main_package) and p != main_package
    ]

    if subpaquetes_inusuales:
        print(f"\n  Subpaquetes inyectados: {len(subpaquetes_inusuales)}")
        for sp in subpaquetes_inusuales:
            nombre_sp = sp[len(main_package) + 1:]
            print(f"    - {sp}")
            if len(nombre_sp) <= 6 and nombre_sp.isalpha():
                puntuacion += 5
                detecciones.append("SUBPACKAGE_SOSPECHOSO")

    dex_data = None
    try:
        with zipfile.ZipFile(ruta, 'r') as z:
            for name in z.namelist():
                if name.endswith('.dex'):
                    dex_data = z.read(name)
                    break
    except Exception as e:
        print(f"  Error extrayendo DEX: {e}")

    if dex_data:
        dex_size = len(dex_data)
        print(f"\n  Tamano DEX: {dex_size:,} bytes")
        if dex_size > 900000:
            puntuacion += 3
            print(f"  DEX grande detectado (+900KB)")

        with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as tmp:
            tmp.write(dex_data)
            tmp.flush()
            inicio = time.time()
            matches = REGLAS_DEX.match(tmp.name)
            elapsed = time.time() - inicio
            if matches:
                print(f"\n  YARA en DEX: {len(matches)} regla(s) activada(s)")
                for i, match in enumerate(matches, 1):
                    print(f"    {i}. {match.rule} ({match.meta.get('severity', 'N/A')})")
                    print(f"       {match.meta.get('description', '')}")
                    for s in match.strings:
                        preview = s.data[:60] if isinstance(s.data, bytes) else str(s.data)[:60]
                        print(f"       - {preview}")
                puntuacion += len(matches) * 5
                detecciones.append("YARA_DEX_POSITIVO")
            else:
                print(f"\n  YARA en DEX: Sin detecciones")
            print(f"  Tiempo escaneo DEX: {elapsed:.4f}s")
            os.unlink(tmp.name)

    n_clases_dex = list(apk.get_dex_names())
    if len(n_clases_dex) > 1:
        puntuacion += 2
        print(f"\n  Multiples DEX: {len(n_clases_dex)}")

    if puntuacion >= 5:
        resultado = "ENVENENADO"
    elif puntuacion >= 2:
        resultado = "SOSPECHOSO"
    else:
        resultado = "LIMPIO"

    return resultado, puntuacion, detecciones


def main():
    print("=" * 60)
    print("  DETECCION DE APKs ENVENENADOS (YARA + Androguard)")
    print("=" * 60)

    resultados = {}
    detalles = {}

    for archivo in ARCHIVOS:
        ruta = os.path.join(DIR, archivo)
        if os.path.exists(ruta):
            res, punt, det = analizar_apk(ruta, archivo)
            resultados[archivo] = res
            detalles[archivo] = (punt, det)

    print(f"\n{'=' * 60}")
    print("  RESUMEN FINAL")
    print(f"{'=' * 60}")

    for archivo, resultado in resultados.items():
        print(f"  {archivo}: {resultado}")

    envenenados = [a for a, r in resultados.items() if r == "ENVENENADO"]
    limpios = [a for a, r in resultados.items() if r == "LIMPIO"]
    sospechosos = [a for a, r in resultados.items() if r == "SOSPECHOSO"]

    if envenenados:
        print(f"\n  APKs ENVENENADOS ({len(envenenados)}):")
        for e in envenenados:
            print(f"    - {e}")
    if limpios:
        print(f"\n  APKs LIMPIOS ({len(limpios)}):")
        for l in limpios:
            print(f"    - {l}")
    if sospechosos:
        print(f"\n  APKs SOSPECHOSOS ({len(sospechosos)}):")
        for s in sospechosos:
            print(f"    - {s}")

    print(f"\n{'=' * 60}")


if __name__ == "__main__":
    main()
