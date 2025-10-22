#!/bin/bash
# Instalação PowerMTA 5.0r1 - Múltiplos Subdomínios no Mesmo IP
# Uso: sudo bash installpmta_multidomains.sh "dominio1|dominio2|dominio3" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP

#########################
# PARÂMETROS DA LINHA DE COMANDO
#########################
DOMINIOS_STRING="$1"
IP="$2"
CLOUDFLARE_KEY="$3"
CLOUDFLARE_EMAIL="$4"
MEUIP="$5"

# Validação de parâmetros
if [ -z "$DOMINIOS_STRING" ] || [ -z "$IP" ] || [ -z "$CLOUDFLARE_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ] || [ -z "$MEUIP" ]; then
    echo "ERRO: Parâmetros insuficientes!"
    echo ""
    echo "Uso: sudo bash installpmta_multidomains.sh \"dominio1|dominio2|dominio3\" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP"
    echo ""
    echo "Exemplo:"
    echo "  sudo bash installpmta_multidomains.sh \"mx.teste.com|mail.teste.com|log.teste.com\" \"203.0.113.10\" \"sua_chave_cf\" \"seu@email.com\" \"seu_ip_admin\""
    echo ""
    exit 1
fi

#########################
# Converte string de domínios em array
#########################
IFS='|' read -ra DOMINIOS <<< "$DOMINIOS_STRING"

# Validação
if [ ${#DOMINIOS[@]} -eq 0 ]; then
    echo "ERRO: Nenhum domínio fornecido!"
    exit 1
fi

#########################
# Extração automática
#########################
DOMINIO_PRINCIPAL="${DOMINIOS[0]}"  # Primeiro domínio = PTR/HELO
ZONA_ROOT=$(echo "$DOMINIO_PRINCIPAL" | rev | cut -d'.' -f1-2 | rev)  # teste.com

# Altera hostname para o domínio principal
hostnamectl set-hostname "$DOMINIO_PRINCIPAL"

# Exibe parâmetros recebidos
echo "=========================================="
echo "   PARÂMETROS RECEBIDOS"
echo "=========================================="
echo "IP do Servidor: $IP"
echo "Domínio PTR/HELO: $DOMINIO_PRINCIPAL"
echo "Zona Cloudflare: $ZONA_ROOT"
echo "Total de Domínios: ${#DOMINIOS[@]}"
echo ""
echo "Domínios configurados:"
for i in "${!DOMINIOS[@]}"; do
    if [ $i -eq 0 ]; then
        echo "  $((i+1)). ${DOMINIOS[$i]} (PTR/HELO)"
    else
        echo "  $((i+1)). ${DOMINIOS[$i]}"
    fi
done
echo "=========================================="
echo ""

#########################
# Funções
#########################
configurar_dns_temp() {
    echo "Configurando DNS temporário..."
    sudo tee /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
}

instalar_dependencias() {
    echo "Instalando dependências..."
    sudo yum install -y unzip openssl curl perl perl-core perl-File-Temp perl-Getopt-Long perl-Storable perl-Time-Local initscripts libcap
    sudo mkdir -p /etc/rc.d/rc{0..6}.d
}

instalar_pmta() {
    echo "Instalando PowerMTA..."
    curl -O http://31.220.76.167/pmta5r1.zip >>/dev/null 2>&1
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

gerar_dkim() {
    local dominio=$1
    local key_file="/etc/pmta/dkim_${dominio}.key"
    local pub_file="dkim_${dominio}.txt"
    
    echo "Gerando DKIM para $dominio..."
    openssl genpkey -algorithm RSA -out "$key_file" 2>/dev/null
    openssl rsa -pubout -in "$key_file" -out "$pub_file" 2>/dev/null
    chown root:pmta "$key_file"
    chmod 640 "$key_file"
    
    # Extrai chave pública
    pubkey=$(sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$pub_file" | sed '1d;$d' | tr -d '\n')
    echo "$pubkey"
}

configurar_pmta() {
    echo "Configurando PowerMTA para múltiplos domínios..."
    
    # Inicia config base
    cat > /etc/pmta/config <<'EOF'
# Pickup (API)
pickup /var/spool/pmta/pickup /var/spool/pmta/badmail

# HTTP Management
http-mgmt-port 1983
http-access 127.0.0.1 admin
EOF
    
    echo "http-access $MEUIP admin" >> /etc/pmta/config
    echo "http-access $IP admin" >> /etc/pmta/config
    
    cat >> /etc/pmta/config <<'EOF'
http-access 0/0 monitor

# Source API
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

<source 0/0>
    log-connections yes
    log-commands no
    allow-unencrypted-plain-auth yes
</source>

sync-msg-create false
sync-msg-update false
run-as-root no
log-file /var/log/pmta/log

<acct-file /var/log/pmta/acct.csv>
    max-size 50M
</acct-file>

<acct-file /var/log/pmta/diag.csv>
    move-interval 1d
    delete-after never
    records t
</acct-file>

spool /var/spool/pmta

# Virtual MTA Pool
<virtual-mta-pool pmta-pool>
EOF
    
    # Gera Virtual-MTAs para cada domínio
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        echo "    virtual-mta vmta-${vmta_name}" >> /etc/pmta/config
    done
    
    echo "</virtual-mta-pool>" >> /etc/pmta/config
    echo "" >> /etc/pmta/config
    
    # Cria cada Virtual-MTA
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        local dkim_key="/etc/pmta/dkim_${dominio}.key"
        
        echo "# Virtual MTA: $dominio" >> /etc/pmta/config
        echo "<virtual-mta vmta-${vmta_name}>" >> /etc/pmta/config
        echo "    smtp-source-host $IP $DOMINIO_PRINCIPAL" >> /etc/pmta/config
        echo "    domain-key default,${dominio},${dkim_key}" >> /etc/pmta/config
        echo "</virtual-mta>" >> /etc/pmta/config
        echo "" >> /etc/pmta/config
    done
    
    # Roteamento por domínio remetente
    echo "# Roteamento por domínio remetente" >> /etc/pmta/config
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        echo "<domain *>" >> /etc/pmta/config
        echo "    <route ${dominio}>" >> /etc/pmta/config
        echo "        use-vmta vmta-${vmta_name}" >> /etc/pmta/config
        echo "    </route>" >> /etc/pmta/config
        echo "</domain>" >> /etc/pmta/config
        echo "" >> /etc/pmta/config
    done
    
    # Anexa o resto do config (backoff, bounces, etc)
    cat config >> /etc/pmta/config
    
    chown root:pmta /etc/pmta/config
}

configurar_dns() {
    echo "Configurando registros DNS..."
    
    # Obtém zone ID da Cloudflare
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$ZONA_ROOT&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_KEY" \
        -H "Content-Type: application/json")
    
    zoneid=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -z "$zoneid" ]; then
        echo "ERRO: Zone ID não encontrado para $ZONA_ROOT"
        return 1
    fi
    
    echo "Zone ID: $zoneid"
    
    # Para cada domínio
    for dominio in "${DOMINIOS[@]}"; do
        local subdominio=$(echo "$dominio" | sed "s/\.$ZONA_ROOT//")
        
        echo "Configurando DNS para: $dominio"
        
        # A record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"A","name":"'"$subdominio"'","content":"'"$IP"'","ttl":1,"proxied":false}' | grep -q "success.*true"
        echo "  ✓ A record"
        sleep 2
        
        # MX record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"MX","name":"'"$subdominio"'","content":"'"$dominio"'","ttl":1,"priority":10,"proxied":false}' | grep -q "success.*true"
        echo "  ✓ MX record"
        sleep 2
        
        # SPF
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"'"$subdominio"'","content":"v=spf1 +a +mx +ip4:'"$IP"' ~all","ttl":1,"proxied":false}' | grep -q "success.*true"
        echo "  ✓ SPF"
        sleep 2
        
        # DKIM
        pubkey=$(gerar_dkim "$dominio")
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"default._domainkey.'"$dominio"'","content":"v=DKIM1; k=rsa; p='"$pubkey"'","ttl":1,"proxied":false}' | grep -q "success.*true"
        echo "  ✓ DKIM"
        sleep 2
        
        # DMARC
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"_dmarc.'"$subdominio"'","content":"v=DMARC1; p=none","ttl":1,"proxied":false}' | grep -q "success.*true"
        echo "  ✓ DMARC"
        sleep 2
    done
}

pickup_config() {
    echo "Configurando Pickup Directory..."
    mkdir -p /var/spool/pmta/pickup
    mkdir -p /var/spool/pmta/badmail
    chown -R pmta:pmta /var/spool/pmta/pickup
    chown -R pmta:pmta /var/spool/pmta/badmail
    chmod 755 /var/spool/pmta/pickup
    chmod 755 /var/spool/pmta/badmail
    chmod +x ./cliente
}

configurar_firewall() {
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        return 0
    fi
    
    echo "Configurando firewall..."
    ZONE="$(firewall-cmd --get-default-zone 2>/dev/null || echo public)"
    
    firewall-cmd --zone="$ZONE" --add-port=1983/tcp || true
    firewall-cmd --zone="$ZONE" --add-port=5000/tcp || true
    firewall-cmd --permanent --zone="$ZONE" --add-port=1983/tcp || true
    firewall-cmd --permanent --zone="$ZONE" --add-port=5000/tcp || true
    firewall-cmd --reload || true
}

configure_bash_monitor() {
    echo "Configurando monitor..."
    CURRENT_DIR=$(pwd)
    MONITOR_SCRIPT="$CURRENT_DIR/process_monitor.sh"
    
    cat > "$MONITOR_SCRIPT" << 'EOFMONITOR'
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

if [[ ! -x "$CLIENTE_CMD" ]]; then
    log_message "ERRO: $CLIENTE_CMD não encontrado ou sem permissão"
    exit 1
fi

log_message "=== Monitor Iniciado ==="
start_process "$CLIENTE_CMD" "cliente"

while true; do
    sleep 30
    if ! is_process_running "$CLIENTE_CMD"; then
        log_message "ALERTA: cliente parado. Reiniciando..."
        start_process "$CLIENTE_CMD" "cliente"
    fi
done
EOFMONITOR

    chmod +x "$MONITOR_SCRIPT"
}

start_monitor() {
    CURRENT_DIR=$(pwd)
    MONITOR_SCRIPT="$CURRENT_DIR/process_monitor.sh"
    
    echo "Iniciando monitor..."
    nohup "$MONITOR_SCRIPT" > /dev/null 2>&1 &
    MONITOR_PID=$!
    echo $MONITOR_PID > "$CURRENT_DIR/process_monitor.pid"
    sleep 3
    
    if kill -0 $MONITOR_PID 2>/dev/null; then
        echo "Monitor rodando (PID: $MONITOR_PID)"
    fi
}

reiniciar_servicos() {
    echo "Reiniciando PowerMTA..."
    systemctl restart pmta pmtahttp
    pmta reload
}

exibir_info() {
    echo ""
    echo "=========================================="
    echo "       INSTALAÇÃO CONCLUÍDA"
    echo "=========================================="
    echo ""
    echo "IP: $IP"
    echo "PTR/HELO: $DOMINIO_PRINCIPAL"
    echo "Zona Cloudflare: $ZONA_ROOT"
    echo ""
    echo "Domínios configurados (${#DOMINIOS[@]}):"
    for dominio in "${DOMINIOS[@]}"; do
        echo "  ✓ $dominio"
    done
    echo ""
    echo "Painel: http://$IP:1983"
    echo "Pickup: /var/spool/pmta/pickup"
    echo "Monitor: tail -f process_monitor.log"
    echo ""
    echo "=========================================="
    echo "         PRÓXIMOS PASSOS"
    echo "=========================================="
    echo "1. CRITICAL: Configure PTR no provedor"
    echo "   PTR: $IP → $DOMINIO_PRINCIPAL"
    echo ""
    echo "2. Aguarde propagação DNS (5-15min)"
    echo ""
    echo "3. Valide a configuração:"
    echo "   bash validar_config.sh"
    echo ""
    echo "4. Teste o envio:"
    echo "   bash criar_testes.sh"
    echo ""
    echo "=========================================="
}

#########################
# Execução
#########################
configurar_dns_temp
instalar_dependencias
instalar_pmta
configurar_pmta
configurar_dns
pickup_config
configurar_firewall
reiniciar_servicos
configure_bash_monitor
start_monitor
exibir_info

# Auto-delete
rm -- "$0"