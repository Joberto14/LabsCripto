#ahora crea un archivo en python que reciba 
# como parametro un string y mande usando 
# scapy un mensaje ping por cada letra del 
# string en la seccion data o payload, es decir, 
# si string de parametro es "hola" debe enviar 
# un ping con la letra h en el campo de data y
#  asi sucesivamente, la ip de origen es 10.31.17.69 
# y la ip de destino es 64.233.190.93

# agregale al char un padding del 10 al 37 en hex

# agregale al paquete que tenga un timestamp, identification coherente, usa la 32385, seq number coherente, id coherente y payload ICMP (8 primeros bytes)


#!/usr/bin/env python3
from scapy.all import IP, ICMP, Raw, send, sendp, IPOption_Timestamp
import sys, time
from datetime import datetime

def send_pings(message, src_ip, dst_ip):
    base_ip_id = 32385   # identificación base para IP
    icmp_id = 12345      # ID fijo para ICMP
    seq_start = 1        # secuencia inicial

    # padding de 0x10 a 0x37
    padding = bytes(range(0x10, 0x37))  
    print(datetime.now().timestamp())
    tmp = int(datetime.now().timestamp() * 10**6)
    print(tmp)
    tmp = tmp.to_bytes(8,'big')
    print(tmp)
    for i, char in enumerate(message, start=seq_start):
        payload = char.encode() + padding  

        pkt = (
            IP(src=src_ip, dst=dst_ip, id=base_ip_id + i, options=[IPOption_Timestamp()]) /
            ICMP(type=8, id=icmp_id, seq=i,ts_ori=int(datetime.now().timestamp()), ts_rx=int(datetime.now().timestamp()), ts_tx=int(datetime.now().timestamp()), options=[IPOption_Timestamp()]) /
            Raw(load=payload)
        )

        # asignamos timestamp al paquete
        pkt.time = time.time()

        send(pkt, verbose=False)
        print(f"[+] Enviado ping con payload: '{char}' | IP.id={base_ip_id+i} | ICMP.id={icmp_id} | seq={i}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <mensaje>")
        sys.exit(1)

    src_ip = "192.168.99.185"
    dst_ip = "172.217.29.110"
    message = sys.argv[1]

    send_pings(message, src_ip, dst_ip)




    