
#ahora genera otro script de python que lea una captura 
# de wireshark y pueda extraer el mensaje que se envio 
# en el payoad de los pings, para esto la ip de origen 
# que envio los paquetes fue la 192.168.99.185 y la ip 
# destino fue la 172.217.192.93 y ademas dado que el 
# mensaje esta cifrado con cesar muestra todas las posibilidades 
# del cifrado(desplazamiento 0 hasta dezplazamiento 25) marcando 
# en verde el string que probablemente corresponde al del mensaje, 
# para esto usa cualquier libreria que pueda resultar util

from scapy.all import rdpcap, IP, ICMP
from colorama import Fore, Style

SRC_IP = "192.168.99.185"
DST_IP = "172.217.192.93"

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def extract_message(pcap_file):
    packets = rdpcap(pcap_file)
    message = ""

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(ICMP):
            ip = pkt[IP]
            if ip.src == SRC_IP and ip.dst == DST_IP and pkt[ICMP].type == 8:  # Echo Request
                raw_payload = bytes(pkt[ICMP].payload)
                if raw_payload:  
                    char = chr(raw_payload[0])  # la primera letra antes del padding
                    message += char
    return message

def guess_shift(candidates):
    """Heurística simple: preferir cadenas con muchas letras y palabras comunes."""
    common_words = ["hello", "ping", "test", "mensaje", "criptografia", "redes"]
    for shift, text in candidates.items():
        low = text.lower()
        if any(word in low for word in common_words):
            return shift
    return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <archivo.pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message(pcap_file)
    print(f"\n[+] Mensaje extraído (sin descifrar): {message}\n")

    candidates = {}
    for shift in range(26):
        candidates[shift] = caesar_cipher(message, shift)

    probable_shift = guess_shift(candidates)

    for shift, text in candidates.items():
        if shift == probable_shift:
            print(f"[{shift:02}] {Fore.GREEN}{text}{Style.RESET_ALL}")
        else:
            print(f"[{shift:02}] {text}")
