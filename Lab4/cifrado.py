#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de cifrado y descifrado utilizando DES, 3DES y AES-256
Librería: pycryptodome (reemplazo moderno de pycrypto)
Instalar con: pip install pycryptodome
"""

from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

def solicitar_iv_valido(nombre_algoritmo, tamano_requerido):
    """
    Solicita el IV y valida que tenga al menos el tamaño requerido.
    Si es menor, pide nuevamente especificando cuántos caracteres se necesitan.
    """
    while True:
        iv_input = input(f"Ingrese el IV para {nombre_algoritmo} (mínimo {tamano_requerido} caracteres): ")
        longitud_actual = len(iv_input.encode('utf-8'))
        
        if longitud_actual < tamano_requerido:
            print(f"❌ IV muy corto. Tiene {longitud_actual} caracteres, se requieren al menos {tamano_requerido} caracteres.")
            print(f"   Por favor, ingrese un IV de al menos {tamano_requerido} caracteres.\n")
        else:
            # Si es válido (igual o mayor), retornar
            return iv_input

def ajustar_clave(clave_input, tamano_requerido, nombre_algoritmo):
    """
    Ajusta la clave al tamaño requerido.
    Si es menor, completa con bytes aleatorios.
    Si es mayor, trunca.
    """
    clave_bytes = clave_input.encode('utf-8')
    longitud_actual = len(clave_bytes)
    
    if longitud_actual < tamano_requerido:
        # Completar con bytes aleatorios
        bytes_faltantes = tamano_requerido - longitud_actual
        bytes_aleatorios = get_random_bytes(bytes_faltantes)
        clave_final = clave_bytes + bytes_aleatorios
        print(f"[{nombre_algoritmo}] Clave completada: {longitud_actual} bytes → {tamano_requerido} bytes (+{bytes_faltantes} aleatorios)")
    elif longitud_actual > tamano_requerido:
        # Truncar
        clave_final = clave_bytes[:tamano_requerido]
        print(f"[{nombre_algoritmo}] Clave truncada: {longitud_actual} bytes → {tamano_requerido} bytes")
    else:
        clave_final = clave_bytes
        print(f"[{nombre_algoritmo}] Clave con tamaño correcto: {tamano_requerido} bytes")
    
    return clave_final

def ajustar_iv(iv_input, tamano_requerido, nombre_algoritmo):
    """
    Ajusta el IV al tamaño requerido (trunca si es mayor).
    """
    iv_bytes = iv_input.encode('utf-8')
    longitud_actual = len(iv_bytes)
    
    if longitud_actual > tamano_requerido:
        iv_final = iv_bytes[:tamano_requerido]
        print(f"[{nombre_algoritmo}] IV truncado: {longitud_actual} bytes → {tamano_requerido} bytes")
    else:
        iv_final = iv_bytes
        print(f"[{nombre_algoritmo}] IV con tamaño correcto: {tamano_requerido} bytes")
    
    return iv_final

def cifrar_des(texto, clave, iv):
    """
    Cifra usando DES (clave de 8 bytes, IV de 8 bytes)
    """
    print("\n" + "=" * 70)
    print("PROCESANDO CIFRADO DES")
    print("=" * 70)
    
    # DES requiere clave de 8 bytes (64 bits)
    clave_final = ajustar_clave(clave, 8, "DES")
    iv_final = ajustar_iv(iv, 8, "DES")
    
    print(f"[DES] Clave final (hex): {binascii.hexlify(clave_final).decode()}")
    print(f"[DES] IV final (hex): {binascii.hexlify(iv_final).decode()}")
    
    # Crear cifrador y cifrar
    cipher = DES.new(clave_final, DES.MODE_CBC, iv_final)
    texto_padded = pad(texto.encode('utf-8'), DES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"[DES] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_final, iv_final

def descifrar_des(texto_cifrado, clave_final, iv_final):
    """
    Descifra usando DES con los mismos parámetros del cifrado
    """
    print("\n" + "─" * 70)
    print("DESCIFRADO DES")
    print("─" * 70)
    
    # Crear cifrador con los mismos parámetros
    cipher = DES.new(clave_final, DES.MODE_CBC, iv_final)
    
    # Descifrar y quitar el padding
    texto_descifrado_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, DES.block_size)
    
    print(f"[DES] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def cifrar_3des(texto, clave, iv):
    """
    Cifra usando 3DES (clave de 24 bytes para 3-key, IV de 8 bytes)
    """
    print("\n" + "=" * 70)
    print("PROCESANDO CIFRADO 3DES")
    print("=" * 70)
    
    # 3DES con 3 claves requiere 24 bytes (192 bits)
    clave_final = ajustar_clave(clave, 24, "3DES")
    iv_final = ajustar_iv(iv, 8, "3DES")
    
    print(f"[3DES] Clave final (hex): {binascii.hexlify(clave_final).decode()}")
    print(f"[3DES] IV final (hex): {binascii.hexlify(iv_final).decode()}")
    
    # Crear cifrador y cifrar
    cipher = DES3.new(clave_final, DES3.MODE_CBC, iv_final)
    texto_padded = pad(texto.encode('utf-8'), DES3.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"[3DES] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_final, iv_final

def descifrar_3des(texto_cifrado, clave_final, iv_final):
    """
    Descifra usando 3DES con los mismos parámetros del cifrado
    """
    print("\n" + "─" * 70)
    print("DESCIFRADO 3DES")
    print("─" * 70)
    
    # Crear cifrador con los mismos parámetros
    cipher = DES3.new(clave_final, DES3.MODE_CBC, iv_final)
    
    # Descifrar y quitar el padding
    texto_descifrado_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, DES3.block_size)
    
    print(f"[3DES] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def cifrar_aes256(texto, clave, iv):
    """
    Cifra usando AES-256 (clave de 32 bytes, IV de 16 bytes)
    """
    print("\n" + "=" * 70)
    print("PROCESANDO CIFRADO AES-256")
    print("=" * 70)
    
    # AES-256 requiere clave de 32 bytes (256 bits)
    clave_final = ajustar_clave(clave, 32, "AES-256")
    iv_final = ajustar_iv(iv, 16, "AES-256")
    
    print(f"[AES-256] Clave final (hex): {binascii.hexlify(clave_final).decode()}")
    print(f"[AES-256] IV final (hex): {binascii.hexlify(iv_final).decode()}")
    
    # Crear cifrador y cifrar
    cipher = AES.new(clave_final, AES.MODE_CBC, iv_final)
    texto_padded = pad(texto.encode('utf-8'), AES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"[AES-256] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_final, iv_final

def descifrar_aes256(texto_cifrado, clave_final, iv_final):
    """
    Descifra usando AES-256 con los mismos parámetros del cifrado
    """
    print("\n" + "─" * 70)
    print("DESCIFRADO AES-256")
    print("─" * 70)
    
    # Crear cifrador con los mismos parámetros
    cipher = AES.new(clave_final, AES.MODE_CBC, iv_final)
    
    # Descifrar y quitar el padding
    texto_descifrado_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, AES.block_size)
    
    print(f"[AES-256] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def main():
    print("=" * 70)
    print("CIFRADO Y DESCIFRADO CON DES, 3DES Y AES-256")
    print("=" * 70)
    print("\nNota: Si la clave es menor al tamaño requerido, se completará con bytes")
    print("      aleatorios. Si es mayor, se truncará.")
    print("      Los vectores de inicialización deben tener el tamaño mínimo requerido.\n")
    
    # Solicitar datos para DES
    print("─" * 70)
    print("### DATOS PARA CIFRADO DES ###")
    print("─" * 70)
    clave_des = input("Ingrese la clave para DES (requiere 8 bytes): ")
    iv_des = solicitar_iv_valido("DES", 8)
    
    # Solicitar datos para 3DES
    print("\n" + "─" * 70)
    print("### DATOS PARA CIFRADO 3DES ###")
    print("─" * 70)
    clave_3des = input("Ingrese la clave para 3DES (requiere 24 bytes): ")
    iv_3des = solicitar_iv_valido("3DES", 8)
    
    # Solicitar datos para AES-256
    print("\n" + "─" * 70)
    print("### DATOS PARA CIFRADO AES-256 ###")
    print("─" * 70)
    clave_aes = input("Ingrese la clave para AES-256 (requiere 32 bytes): ")
    iv_aes = solicitar_iv_valido("AES-256", 16)
    
    # Solicitar texto a cifrar
    print("\n" + "─" * 70)
    print("### TEXTO A CIFRAR ###")
    print("─" * 70)
    texto = input("Ingrese el texto a cifrar: ")
    
    if not texto:
        print("\n❌ Error: El texto a cifrar no puede estar vacío")
        return
    
    # Cifrar y descifrar con DES
    try:
        cifrado_des, clave_des_final, iv_des_final = cifrar_des(texto, clave_des, iv_des)
        descifrar_des(cifrado_des, clave_des_final, iv_des_final)
    except Exception as e:
        print(f"\n❌ [DES] Error: {str(e)}")
    
    # Cifrar y descifrar con 3DES
    try:
        cifrado_3des, clave_3des_final, iv_3des_final = cifrar_3des(texto, clave_3des, iv_3des)
        descifrar_3des(cifrado_3des, clave_3des_final, iv_3des_final)
    except Exception as e:
        print(f"\n❌ [3DES] Error: {str(e)}")
    
    # Cifrar y descifrar con AES-256
    try:
        cifrado_aes, clave_aes_final, iv_aes_final = cifrar_aes256(texto, clave_aes, iv_aes)
        descifrar_aes256(cifrado_aes, clave_aes_final, iv_aes_final)
    except Exception as e:
        print(f"\n❌ [AES-256] Error: {str(e)}")
    
    print("\n" + "=" * 70)
    print("✅ CIFRADO Y DESCIFRADO COMPLETADO")
    print("=" * 70)

if __name__ == "__main__":
    main()
