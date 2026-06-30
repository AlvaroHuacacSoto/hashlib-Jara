import hashlib
import os
import time

DIR = "/home/alim/exposicion final/APKs"
ARCHIVOS = ["CairosOriginal.apk", "CairosVenom.apk"]


def calcular_hashes(ruta):
    algoritmos = {
        "MD5": hashlib.md5(),
        "SHA-1": hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512(),
    }

    try:
        with open(ruta, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for h in algoritmos.values():
                    h.update(chunk)
        return {nombre: obj.hexdigest() for nombre, obj in algoritmos.items()}
    except Exception as e:
        return {"Error": str(e)}


def comparar_hashes(h1, h2):
    diffs = {}
    for alg in h1:
        if alg in h2 and "Error" not in (h1[alg], h2[alg]):
            diffs[alg] = h1[alg] != h2[alg]
    return diffs


def main():
    print("=" * 80)
    print("COMPARACION DE HASHES - APK ORIGINAL vs APK ENVENENADO")
    print("=" * 80)

    resultados = {}
    tamanos = {}

    for archivo in ARCHIVOS:
        ruta = os.path.join(DIR, archivo)
        if not os.path.exists(ruta):
            print(f"  {archivo}: NO ENCONTRADO")
            continue

        inicio = time.time()
        hashes = calcular_hashes(ruta)
        elapsed = time.time() - inicio

        tamanos[archivo] = os.path.getsize(ruta)
        resultados[archivo] = hashes

        print(f"\n  {archivo}")
        print(f"  Tamano: {os.path.getsize(ruta):,} bytes")
        print(f"  Tiempo: {elapsed:.3f}s")
        for alg, valor in hashes.items():
            print(f"    {alg:8}: {valor}")

    if len(resultados) == 2:
        original = resultados["CairosOriginal.apk"]
        envenenado = resultados["CairosVenom.apk"]
        diffs = comparar_hashes(original, envenenado)

        print("\n" + "=" * 80)
        print("RESULTADO DE LA COMPARACION")
        print("=" * 80)

        iguales = True
        for alg, diferente in diffs.items():
            if diferente:
                print(f"  {alg}: DISTINTO - El archivo fue modificado")
                iguales = False
            else:
                print(f"  {alg}: IGUAL")

        if iguales:
            print("\n  Los archivos son identicos (mismo contenido).")
        else:
            print("\n  Los archivos SON DIFERENTES - La inyeccion del payload")
            print("  modifico el contenido del APK.")

            print("\n" + "-" * 40)
            print("EFECTO AVALANCHA (SHA-256):")
            h1 = bytes.fromhex(original["SHA-256"])
            h2 = bytes.fromhex(envenenado["SHA-256"])
            bits_distintos = sum(bin(a ^ b).count("1") for a, b in zip(h1, h2))
            total_bits = len(h1) * 8
            porcentaje = (bits_distintos / total_bits) * 100
            print(f"  Bits diferentes: {bits_distintos}/{total_bits} ({porcentaje:.1f}%)")
            print("  Un cambio minimo en el archivo produce un hash")
            print("  completamente diferente.")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
