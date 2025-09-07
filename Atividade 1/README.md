Port Scanner (TCP/UDP) — Linux-first

Descrição
- Ferramenta simples para varredura de portas TCP e UDP em um ou mais alvos, com técnicas básicas de detecção.
- Foco em Linux. Funciona em outros sistemas com limitações. TCP SYN (semi-aberto) é opcional e requer root + Scapy.

Principais Recursos
- Varredura TCP (connect) por padrão; TCP SYN se disponível (root+Scapy), com fallback automático para connect.
- Varredura UDP por sondagem: classifica como open, closed, ou open|filtered (sem resposta/filtrado).
- Aceita IPs, hostnames e redes CIDR (ex.: 192.168.1.0/24).
- Concurrency com ThreadPool para eficiência.

Requisitos
- Python 3.8+
- Linux recomendado.
- Opcional: Scapy para TCP SYN: `pip install scapy` (executar como root).

Uso Rápido

1) Ajuda
```
python3 portscan.py --help
```

2) Escanear TCP e UDP (padrão) nas portas 1–1024
```
python3 portscan.py 192.168.1.10
```

3) Especificar portas e múltiplos alvos
```
python3 portscan.py 10.0.0.5 10.0.0.10 -p 22,53,80,443,8000-8100
```

4) Somente TCP ou UDP
```
python3 portscan.py 192.168.0.1 --tcp -p 1-1024
python3 portscan.py 192.168.0.1 --udp -p 53,67-69
```

5) TCP SYN (Linux + root + Scapy)
```
sudo python3 portscan.py 192.168.0.1 --tcp --syn -p 1-1024
```

6) Incluir portas fechadas na saída
```
python3 portscan.py 127.0.0.1 -p 1-200 --show-closed
```

Notas Técnicas
- TCP connect: usa `socket.connect_ex`. Marca aberto quando conecta; demais erros tratados como fechado; timeout => filtrado.
- TCP SYN: envia SYN e interpreta respostas (SYN/ACK=open, RST/ACK=closed, sem resposta=filtered). Envia RST para limpar estado.
- UDP: envia datagrama e tenta `recv()`; se receber payload => open; ICMP Port Unreachable normalmente vira `ConnectionRefused` (closed); sem resposta => open|filtered.
- DNS/hostnames são resolvidos para IPv4; para redes CIDR, hosts são expandidos (limite 2^20 endereços).

Limitações
- UDP pode requerer sondas específicas por serviço para melhor precisão. Aqui é genérico.
- Sem privilégios de root e/ou sem Scapy, o método TCP SYN não é usado.
- Em alguns SOs, erros ICMP em UDP não são propagados; resultados podem tender a open|filtered.

Desempenho
- Controle o paralelismo com `--workers` e `--timeout` conforme a rede/host alvo. Valores muito altos podem gerar perdas ou bloqueios.

Segurança e Ética
- Utilize somente em redes/alvos autorizados. Varreduras podem ser detectadas e bloqueadas por firewalls/IDS.

Estrutura
- Script principal: `portscan.py`

