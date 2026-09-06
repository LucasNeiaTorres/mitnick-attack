# mitnick-attack

> **In short.** A lab reproduction of the 1994 Kevin Mitnick attack against
> Tsutomu Shimomura's machine: forge the IP of a trusted host, complete a TCP
> handshake you cannot see the other half of, and run a command on the victim
> through `rsh` — the address-trust login (`.rhosts`) that Unix used before SSH.
> Built on the SEED Labs image with three Docker containers on one isolated LAN.
> Scapy does the packet crafting. It is a classroom exercise: the attack only
> works against address-based trust and against TCP stacks that let an outsider
> know the connection's sequence number — neither of which survives on a
> patched system today (see the last section).

Reprodução, em laboratório fechado, do ataque histórico que Kevin Mitnick
desferiu contra a estação de Tsutomu Shimomura em 1994. É o **Mitnick Attack
Lab** do [SEED Labs](https://seedsecurity.org/), feito como trabalho de uma
disciplina de segurança computacional.

O ataque tem uma ideia central: em máquinas Unix da época, o login `rlogin`/`rsh`
podia dispensar senha se o cliente viesse de um endereço IP declarado *confiável*
no arquivo `~/.rhosts`. A autenticação era **o endereço de origem** — e endereço
de origem se forja. O atacante finge ser o host confiável, abre uma conexão TCP
com esse IP falso, e manda um comando pela conexão. Como ele forja o IP, as
respostas do alvo não voltam para ele; o atacante precisa **fechar o handshake às
cegas** e **calar o verdadeiro host confiável** para que ele não derrube a conexão
forjada. Era isso que tornava o ataque difícil — e é isso que este repositório
reconstrói.

---

## O que está reproduzido aqui

O cenário tem três máquinas numa mesma rede isolada (`10.9.0.0/24`):

| Papel | Container | IP | O que é |
|---|---|---|---|
| Atacante | `seed-attacker` | `10.9.0.1` | quem forja os pacotes (o "Mitnick") |
| Vítima | `x-terminal` | `10.9.0.5` | a estação-alvo, roda o servidor `rsh` (`inetd`) |
| Host confiável | `trusted-server` | `10.9.0.6` | o endereço em quem a vítima confia |

A vítima é preparada com `echo 10.9.0.6 > ~/.rhosts`: ela passa a confiar em
qualquer login que **diga vir** de `10.9.0.6`. O atacante então se faz passar por
`10.9.0.6`.

O `mitnick.py` (Scapy) executa a sessão TCP forjada de ponta a ponta:

1. **IP spoofing + início do handshake.** Envia um `SYN` para a porta 514 (o
   serviço `shell`/`rshd`) do x-terminal com o IP de origem **forjado** como o do
   trusted-server, da porta de origem privilegiada 1023.
2. **Fecha o handshake.** O x-terminal responde com o `SYN/ACK` — que, por
   endereçamento, vai para `10.9.0.6`. O atacante o intercepta (ver adiante),
   **lê o número de sequência real** desse pacote e responde com o `ACK`
   correspondente (`ack = seq + 1`). A conexão TCP está estabelecida.
3. **Injeta o comando via `rsh`.** Manda o payload do protocolo `rsh`
   —`9090\x00root\x00root\x00echo + + > ~/.rhosts\x00`— num pacote `PSH/ACK`. O
   comando `echo + + > ~/.rhosts` reescreve o arquivo de confiança da vítima para
   `+ +`: **qualquer host, qualquer usuário**, sem senha. É o backdoor.
4. **Atende o canal secundário do `rsh`.** O `rsh` abre uma segunda conexão, do
   servidor de volta ao cliente, para o `stderr` (a porta `9090` anunciada no
   payload). Como o "cliente" é o IP forjado, essa conexão também chega ao
   atacante, que responde ao `SYN` com um `SYN/ACK` e ao `FIN/ACK` com um
   `FIN/ACK`, mantendo o protocolo satisfeito.

Feito isso, a vítima confia em todo mundo, e o atacante entra direto com `rsh`.

**Bibliotecas:** Scapy para forjar e farejar pacotes. **Ambiente:** SEED Ubuntu
(`handsonsecurity/seed-ubuntu:large`), orquestrado por Docker Compose, com
`rsh-redone-client`/`rsh-redone-server` instalados para prover o `rlogin`/`rsh`
que nenhum sistema atual traz.

---

## O detalhe que vale a leitura

Duas dificuldades definem o ataque, e a solução escolhida aqui difere da de 1994
em ambas — de propósito, por causa do laboratório.

**1. De onde vem o número de sequência.** Uma conexão TCP só avança se cada lado
souber o número de sequência do outro. O atacante forjou a origem, então o
`SYN/ACK` da vítima não é endereçado a ele: ele não deveria vê-lo. No ataque
original, Mitnick estava **remoto** e teve de **prever** o número de sequência
inicial (ISN) da vítima estatisticamente, porque as pilhas TCP da época geravam
ISNs incrementais e previsíveis. Aqui, atacante e vítima estão na **mesma LAN**,
então o `mitnick.py` **fareja** (`sniff`) o `SYN/ACK` que passa pela rede e
**lê** o número de sequência real, em vez de adivinhá-lo. É a mesma quebra de
confiança do ataque histórico, mas a parte "difícil" — a predição do ISN — é
substituída por escuta local, que é o que o ambiente de laboratório permite.

**2. Por que o host confiável precisa ficar mudo.** O `SYN/ACK` da vítima é
endereçado a `10.9.0.6`, o trusted-server *de verdade*. Se ele o recebesse, seu
núcleo não teria nenhum socket aberto esperando aquela conexão e responderia com
um `RST` — que derrubaria a conexão forjada antes do comando chegar. O ataque
original silenciava o host confiável com um **SYN flood**, entupindo sua fila de
conexões. Este trabalho usa outra técnica: **ARP spoofing** (`arpSpoofing.py`).
Ele envenena a cache ARP do x-terminal, associando o IP `10.9.0.6` ao **MAC do
atacante**; assim, tudo que a vítima manda "para o host confiável" chega, na
verdade, ao atacante. E o `mitnick.py` **desliga o IP forwarding**
(`echo 0 > /proc/sys/net/ipv4/ip_forward`) para **não** repassar esses pacotes ao
trusted-server real — que, por nunca vê-los, nunca manda o `RST`. O silêncio, aqui,
não vem de afogar o host confiável: vem de sequestrar o caminho até ele e não o
encaminhar.

Detalhe operacional registrado pelo autor: o `arpSpoofing.py` precisa rodar
**durante** o `mitnick.py`, porque o x-terminal corrige sozinho sua tabela ARP
depois de um tempo; por isso o envenenamento é reenviado a cada 0,2 s.

---

## O que NÃO está implementado

- **Não há SYN flood.** A técnica clássica de silenciar o host confiável não foi
  usada; o silêncio vem do ARP spoofing + IP forwarding desligado.
- **Não há predição de ISN.** O número de sequência é **farejado** na LAN, não
  previsto — que é a simplificação que a topologia local permite e que a máquina
  remota de 1994 não tinha.
- É um exercício de laboratório: sem interface, sem parametrização, sem
  tratamento de erro além do necessário. Os IPs, as portas e o comando do backdoor
  estão fixos no código.

---

## Como reproduzir (só no laboratório)

Exige o ambiente do SEED Labs; roda inteiro dentro dos contêineres, numa rede
isolada. Não aponte isto para nada fora dele.

```bash
docker compose build
docker compose up -d
```

Depois, seguindo o roteiro do autor (`volumes/reproducao.txt`):

1. No `x-terminal`, estabeleça a relação de confiança: `echo 10.9.0.6 > ~/.rhosts`.
2. No `seed-attacker`, dentro de `/volumes`, rode `python3 arpSpoofing.py`.
3. **Enquanto ele roda**, em outro terminal do `seed-attacker`, rode
   `python3 mitnick.py`.
4. Após alguns segundos, o `.rhosts` da vítima já é `+ +`, e o atacante entra
   direto por `rsh`.

O `arpSpoofing.py` tem de continuar rodando junto do `mitnick.py`: o x-terminal
reconstrói a tabela ARP correta sozinho se o envenenamento parar.

---

## Por que isto não funciona mais hoje

Este ataque é peça de museu — e entender *por que* ele morreu é o que faz dele
material didático. Cada perna do ataque bate hoje numa defesa padrão:

- **Fim do `rlogin`/`rsh` e da confiança por endereço.** A autenticação por
  `~/.rhosts` — confiar num IP — foi substituída pelo **SSH**, que autentica por
  **chave criptográfica** de host e de usuário. Um endereço de origem forjado não
  prova mais nada; não há em que se passar. Esta é a defesa que sozinha já encerra
  o ataque: sem `rsh`, não há porta 514 para invadir.
- **ISN aleatório (RFC 6528).** Pilhas TCP modernas geram o número de sequência
  inicial de forma imprevisível. A **predição** de ISN — a parte genial do ataque
  original — deixou de ser viável contra um alvo remoto.
- **SYN cookies.** Defendem a fila de conexões contra o SYN flood, tirando a
  eficácia da técnica clássica de silenciar o host confiável.
- **Filtragem de ingresso (BCP 38 / RFC 2827).** Redes bem configuradas descartam
  pacotes cujo IP de origem não pertence à rede de onde vêm, o que bloqueia o IP
  spoofing entre redes.
- **Defesas de camada 2.** Em redes gerenciadas, *Dynamic ARP Inspection* e
  *port security* detêm o ARP spoofing que aqui silencia o host confiável.

Ou seja: o ataque só se sustenta contra um sistema **desatualizado**, com serviços
legados ligados, numa rede sem essas proteções — exatamente as condições que o
laboratório recria artificialmente.

---

## Aviso legal e ético

Isto é um experimento de laboratório, executado numa rede isolada de contêineres,
contra máquinas do próprio autor. **Executar qualquer parte disto contra
computador de terceiro, sem autorização expressa, é crime** (no Brasil, invasão de
dispositivo informático, art. 154-A do Código Penal). IP spoofing, ARP spoofing e
sequestro de sessão TCP fora de um ambiente controlado e autorizado não têm uso
legítimo. O código está aqui para estudar como o ataque funcionava e como as
defesas modernas o encerraram — nada além disso.

---

## Estrutura

```
mitnick-attack/
  docker-compose.yml            três contêineres: atacante, x-terminal, trusted-server
  image_ubuntu_mitnick/
    Dockerfile                  imagem SEED Ubuntu + rsh-redone (cliente e servidor)
  volumes/                      montado no atacante
    arpSpoofing.py              envenena a cache ARP do x-terminal (silencia o host confiável)
    mitnick.py                  o ataque: SYN spoofado, handshake por sniff do ISN, rsh, backdoor
    reproducao.txt              o roteiro de execução do autor
    identificacao.txt           identificação do autor (trabalho acadêmico)
  LICENSE                       MIT
```
