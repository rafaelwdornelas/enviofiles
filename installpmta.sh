#!/bin/bash
# Description: Script para instalação do PowerMTA 5.0r1 no  AlmaLinux 8 a 9 com Virtualmin
# Uso: sudo bash installpmta.sh <DOMINIO> <IP> <CLOUDFLARE> <CLOUDFLARE_EMAIL> <MEUIP>

# Configura DNS temporário para 8.8.8.8 e 1.1.1.1
echo "Configurando DNS temporário..."
sudo tee /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

# Variáveis principais
DOMINIO="$1"
IP="$2"
CLOUDFLARE="$3"
CLOUDFLARE_EMAIL="$4"
MEUIP="$5"
smtp_username="smtp.$DOMINIO"
smtp_password="2Xg9nPIqC1ZP"
# Extrai subdomínio do domínio principal (por exemplo, se DOMINIO=exemplo.com, SUBDOMINIO=exemplo)
SUBDOMINIO=$(echo "$DOMINIO" | cut -d'.' -f1)

# altera hostname
hostnamectl set-hostname $DOMINIO

#########################
# Funções do Script
#########################
exibir_parametros() {
    echo "Nome do Domínio: $DOMINIO"
    echo "IP do Servidor: $IP"
    echo "Chave da Cloudflare: $CLOUDFLARE"
    echo "Email da Cloudflare: $CLOUDFLARE_EMAIL"
    echo "Usuário SMTP: $smtp_username"
    echo "Senha SMTP: $smtp_password"
    echo "INSTALAÇÂO CONCLUIDA"
}

instalar_dependencias() {
    echo "Instalando Dependencias..."
    # Atualiza o sistema
    # sudo yum install -y epel-release
    # Pacotes básicos
    sudo yum install -y unzip openssl curl
    # Perl
    sudo yum install -y perl
    # Dependências do PowerMTA
    sudo yum install -y perl-core perl-File-Temp perl-Getopt-Long perl-Storable perl-Time-Local initscripts
    # Dependências do PowerMTA
    sudo yum install libcap -y

    sudo mkdir -p /etc/rc.d/rc{0..6}.d
}

instalar_pmta() {
    echo "Instalando PowerMTA..."
    # faz o download do arquivo zipado do PowerMTA em http://31.220.76.167/pmta5r1.zip
    curl -O http://209.126.6.244/pmta5r1.zip >>/dev/null 2>&1
    unzip pmta5r1.zip
    rpm -ivh PowerMTA5.0.rpm >>/dev/null 2>&1
    rpm -ivh PowerMTA-snmp-5.0r1-201909161531.x86_64.rpm >>/dev/null 2>&1
    service pmta stop
    service pmtahttp stop
    rm -rf /usr/sbin/pmtad /usr/sbin/pmtahttpd
    cp usr/sbin/* /usr/sbin/
    chmod -R 777 /usr/sbin/pmta /usr/sbin/pmtad /usr/sbin/pmtahttpd
    cp license /etc/pmta
    chown root:pmta /etc/pmta/license
    rm -rf /etc/pmta/config
}

configurar_pmta() {
    echo "Configurando arquivos do PowerMTA..."
    # Cria a configuração inicial
    echo "postmaster info@$DOMINIO" >>config
    echo "<virtual-mta-pool pmta-pool>" >>smtp_pool

    # Cria o arquivo smtp_details com a configuração do serviço
    cat <<EOF >>smtp_details
http-mgmt-port 1983
http-access 127.0.0.1 admin
http-access $MEUIP admin
http-access $IP admin
http-access 0/0 monitor

############################################################################
# END: OTHER OPTIONS
############################################################################

################################################ ############################
# BEGIN: USERS/VIRTUAL-MTA / VIRTUAL-MTA-POOL /  VIRTUAL-PMTA-PATTERN
################################################ ############################
#<spool /var/spool/pmta>
#</spool>

<smtp-user $smtp_username>
        password $smtp_password
        source {smtpuser-auth}
</smtp-user>
<source {smtpuser-auth}>
        smtp-service yes
        always-allow-relaying yes
        require-auth true
        process-x-virtual-mta yes
        default-virtual-mta pmta-pool
        remove-received-headers true
        add-received-header false
        hide-message-source true
</source>
EOF

    echo "smtp-listener $IP:2525" >>smtp_details

    # Adiciona a parte dos Virtual MTAs
    cat <<EOF >>smtp_details
#BEGIN VIRTUAL MTAS 
<virtual-mta pmta-vmta>
smtp-source-host $IP $DOMINIO
domain-key default,*,/etc/pmta.key
#domain-key mailer,*,/var/cpanel/domain_keys/private/$DOMINIO
</virtual-mta> 
# <domain $DOMINIO>
# smtp-hosts [127.0.0.1]:25
# </domain>
#END VIRTUAL MTAS
EOF

    echo "virtual-mta pmta-vmta" >>smtp_pool

    # Cria os registros DNS no arquivo rdns_records
    echo -e "$DOMINIO.    IN      A       $IP\n" >>rdns_records
    echo -e "mail.$SUBDOMINIO.    IN      A       $IP\n" >>rdns_records
    echo -e "$SUBDOMINIO.    IN      MX       mail.$DOMINIO\n" >>rdns_records
    echo -e "_dmarc.$SUBDOMINIO.    IN      TXT       v=DMARC1; p=none\n" >>rdns_records
    echo -e "$SUBDOMINIO.    IN      TXT       v=spf1 +a +mx +ip4:$IP ~all\n" >>rdns_records

    echo "</virtual-mta-pool>" >>smtp_pool

    # Junta os arquivos de configuração
    cat smtp_details >>config
    cat smtp_pool >>config

    cat <<EOF >>config
################################################ ############################
# END: USERS/VIRTUAL-MTA / VIRTUAL-MTA-POOL /  VIRTUAL-PMTA-PATTERN
################################################ ############################
<source 127.0.0.1>
    always-allow-api-submission yes
    add-message-id-header yes
    retain-x-job yes
    retain-x-virtual-mta yes
    verp-default yes
    process-x-envid yes
    process-x-job yes
    jobid-header X-Mailer-RecptId
    process-x-virtual-mta yes
</source>

#<domain *>
#smtp-hosts [127.0.0.1]:2525
#</domain>
EOF

    # Copia o arquivo config para o diretório do PowerMTA e ajusta as permissões
    cp config /etc/pmta/
    chown root:pmta /etc/pmta/config
}

configurar_dkim() {
    echo "Configurando DKIM..."
    openssl genpkey -algorithm RSA -out private.pem
    openssl rsa -pubout -in private.pem -out dkim.txt
    # Copia a chave privada para o local do PowerMTA e ajusta as permissões
    cat private.pem >/etc/pmta.key
    chown root:pmta /etc/pmta.key
    chmod 640 /etc/pmta.key

    # Extrai a chave pública removendo cabeçalho, rodapé e quebras de linha
    pubkey=$(sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' dkim.txt | sed '1d;$d' | tr -d '\n')

    # Adiciona os registros DKIM aos registros DNS
    echo -e "default._domainkey.$DOMINIO IN TXT \"v=DKIM1; k=rsa; p=${pubkey}\"\n" >>rdns_records
}

reiniciar_servicos() {
    echo "Reiniciando serviços do PowerMTA..."
    systemctl restart pmta pmtahttp
    pmta reload
}

adicionar_registros_cloudflare() {
    echo "Adicionando registros no Cloudflare..."

    # Determina a zone removendo o subdomínio, se houver (ex.: mail.exemplo.com → exemplo.com)
    if [[ $(echo "$DOMINIO" | awk -F'.' '{print NF}') -gt 2 ]]; then
        zone=$(echo "$DOMINIO" | cut -d'.' -f2-)
    else
        zone="$DOMINIO"
    fi
    echo "Zone: $zone"

    # Obtém a resposta completa da API do Cloudflare
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$zone&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json")

    # Remove as quebras de linha para facilitar o processamento
    response=$(echo "$response" | tr -d '\n')

    # Extrai o zone ID: procura pela ocorrência de "id":"<valor>" seguida de "name":"mercadocentralbr.com"
    zoneid=$(echo "$response" | sed -n 's/.*"id":"\([^"]*\)".*"name":"'"$zone"'".*/\1/p')
    sleep 5

    # Cria registro A para o domínio
    create_dns_a=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json" \
        --data '{"type":"A","name":"'"$SUBDOMINIO"'","content":"'"$IP"'","ttl":1,"proxied":false}')
    echo "$create_dns_a"
    echo "Registro A adicionado!"
    sleep 5

    # Cria registro MX apontando para DOMINIO
    create_dns_mx=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json" \
        --data '{"type":"MX","name":"'"$SUBDOMINIO"'","content":"'"$DOMINIO"'","ttl":1,"priority":10,"proxied":false}')
    echo "$create_dns_mx"
    echo "Registro MX adicionado!"
    sleep 5

    # Cria registro SPF para o domínio
    create_dns_spf=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json" \
        --data '{"type":"TXT","name":"'"$SUBDOMINIO"'","content":"v=spf1 +a +mx +ip4:'"$IP"' ~all","ttl":1,"proxied":false}')
    echo "$create_dns_spf"
    echo "Registro SPF adicionado!"
    sleep 5

    # Extrai a chave DKIM pública do arquivo dkim.txt gerado anteriormente
    DKIM=$(sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' dkim.txt | sed '1d;$d' | tr -d '\n')

    # Cria registro DKIM (utilizando "mail._domainkey.DOMINIO" conforme o exemplo)
    create_dns_dkim=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json" \
        --data '{"type":"TXT","name":"default._domainkey.'"$DOMINIO"'","content":"v=DKIM1; h=sha256; k=rsa; p='"$DKIM"'","ttl":1,"proxied":false}')
    echo "$create_dns_dkim"
    echo "Registro DKIM adicionado!"
    sleep 5

    # Cria registro DMARC para o domínio
    create_dns_dmarc=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE" \
        -H "Content-Type: application/json" \
        --data '{"type":"TXT","name":"_dmarc.'"$SUBDOMINIO"'","content":"v=DMARC1; p=none","ttl":1,"proxied":false}')
    echo "$create_dns_dmarc"
    echo "Registro DMARC adicionado!"
    sleep 5
}

configurar_dns_temp() {
    echo "Configurando DNS temporário..."
    sudo tee /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

    count=0
    max_attempts=30

    while true; do
        if grep -q "nameserver 8.8.8.8" /etc/resolv.conf && grep -q "nameserver 1.1.1.1" /etc/resolv.conf; then
            echo "Arquivo /etc/resolv.conf atualizado com sucesso."
            break
        else
            echo "Aguardando atualização de /etc/resolv.conf... Tentativa $((count + 1)) de $max_attempts"
            sleep 1
            ((count++))
            if [ $count -ge $max_attempts ]; then
                echo "DNS não alterado após $max_attempts tentativas. Fechando o script."
                exit 1
            fi
        fi
    done
}

configurar_firewall_firewalld() {
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewall-cmd não encontrado; pulando abertura de portas."
        return 0
    fi

    echo "Configurando firewalld (abrindo 1983/tcp, 5000/tcp e 2525/tcp)..."
    # zona padrão (fallback em 'public' se não conseguir pegar)
    local ZONE
    ZONE="$(firewall-cmd --get-default-zone 2>/dev/null || echo public)"

    # Runtime (imediato)
    firewall-cmd --zone="$ZONE" --add-port=1983/tcp || true
    firewall-cmd --zone="$ZONE" --add-port=5000/tcp || true
    firewall-cmd --zone="$ZONE" --add-port=2525/tcp || true

    # Permanente
    firewall-cmd --permanent --zone="$ZONE" --add-port=1983/tcp || true
    firewall-cmd --permanent --zone="$ZONE" --add-port=5000/tcp || true
    firewall-cmd --permanent --zone="$ZONE" --add-port=2525/tcp || true

    # Aplicar permanente
    firewall-cmd --reload || true

    echo "Portas abertas na zona '$ZONE':"
    firewall-cmd --zone="$ZONE" --list-ports || true
}

# NOVA VERSÃO - configure_bash_monitor melhorada
configure_bash_monitor() {
  echo "Configurando monitor em bash..."
  
  CURRENT_DIR=$(pwd)
  MONITOR_SCRIPT="$CURRENT_DIR/process_monitor.sh"
  
  cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash

WORK_DIR="$(dirname "$0")"
LOG_FILE="$WORK_DIR/process_monitor.log"
CLIENTE_CMD="$WORK_DIR/cliente"

cd "$WORK_DIR"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

is_process_running() {
    pgrep -f "$1" > /dev/null 2>&1
}

start_process() {
    local cmd="$1"
    local name="$2"
    
    if is_process_running "$cmd"; then
        log_message "$name já está rodando"
        return 0
    fi
    
    log_message "Iniciando $name..."
    nohup $cmd > /dev/null 2>&1 &
    
    sleep 3
    
    if is_process_running "$cmd"; then
        log_message "$name iniciado (PID: $(pgrep -f "$cmd"))"
    else
        log_message "ERRO: Falha ao iniciar $name"
    fi
}

cleanup() {
    log_message "Encerrando processos..."
    pkill -f "$CLIENTE_CMD" 2>/dev/null
    log_message "Monitor encerrado."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Verificar executável
if [[ ! -x "$CLIENTE_CMD" ]]; then
    log_message "ERRO: $CLIENTE_CMD não encontrado ou sem permissão"
    exit 1
fi

log_message "=== Monitor Iniciado ==="
log_message "Executável: cliente"
log_message "Intervalo: 30s"

# Primeira execução
start_process "$CLIENTE_CMD" "cliente"

# Loop de monitoramento
while true; do
    sleep 30
    
    if ! is_process_running "$CLIENTE_CMD"; then
        log_message "ALERTA: cliente parado. Reiniciando..."
        start_process "$CLIENTE_CMD" "cliente"
    fi
done
EOF

  chmod +x "$MONITOR_SCRIPT"
  echo "Monitor criado: $MONITOR_SCRIPT"
}

pickup_config() {
     echo "Configurando Pickup Directory e API..."
    
    # 1. Criar diretórios
    mkdir -p /var/spool/pmta/pickup
    mkdir -p /var/spool/pmta/badmail

    # 2. Permissões
    chown -R pmta:pmta /var/spool/pmta/pickup
    chown -R pmta:pmta /var/spool/pmta/badmail
    chmod 755 /var/spool/pmta/pickup
    chmod 755 /var/spool/pmta/badmail

    # 3. Tornar executável o cliente (servidor API)
    chmod +x ./cliente

}

# Função para iniciar o monitor
start_monitor() {
  CURRENT_DIR=$(pwd)
  MONITOR_SCRIPT="$CURRENT_DIR/process_monitor.sh"
  
  echo "Iniciando monitor de processos em background..."
  
  # Iniciar o monitor em background usando nohup
  nohup "$MONITOR_SCRIPT" > /dev/null 2>&1 &
  MONITOR_PID=$!
  
  # Salvar PID do monitor para poder parar depois se necessário
  echo $MONITOR_PID > "$CURRENT_DIR/process_monitor.pid"
  
  echo "Monitor iniciado com PID: $MONITOR_PID"
  echo "Para parar o monitor: kill \$(cat $CURRENT_DIR/process_monitor.pid)"
  echo "Para ver logs: tail -f $CURRENT_DIR/process_monitor.log"
  
  # Aguardar um momento para verificar se o monitor iniciou corretamente
  sleep 3
  
  if kill -0 $MONITOR_PID 2>/dev/null; then
    echo "Monitor rodando corretamente!"
  else
    echo "ERRO: Monitor não está rodando. Verifique os logs."
  fi
}

#########################
# Execução do Script
#########################
configurar_dns_temp
instalar_dependencias
instalar_pmta
configurar_pmta
configurar_dkim
pickup_config            # ← MOVER PARA AQUI (antes de reiniciar)
configurar_firewall_firewalld
reiniciar_servicos       # ← Agora reinicia COM dirs criados
adicionar_registros_cloudflare
configure_bash_monitor
start_monitor
exibir_parametros

# Apaga o próprio script
rm -- "$0"
