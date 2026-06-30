# hashlib + YARA - Detección de APKs envenenados

Herramientas para análisis forense de APKs:

- **comparar_hashes.py** - Calcula y compara hashes MD5, SHA-1, SHA-256, SHA-512 entre APK original y envenenado
- **detector_yara.py** - Detecta APKs infectados con payload de Metasploit usando YARA + Androguard

## Requisitos

```bash
python -m venv venv
source venv/bin/activate
pip install yara-python androguard
```

## Uso

```bash
python comparar_hashes.py
python detector_yara.py
```
