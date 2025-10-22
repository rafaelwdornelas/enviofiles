#!/bin/bash
# Instalação PowerMTA 5.0r1 - Múltiplos Subdomínios (DKIM CORRIGIDO)
# Uso: sudo bash installpmta_mult.sh "dom1|dom2|dom3" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP

# Configura DNS temporário
echo "Configurando DNS temporário..."
sudo tee /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

#########################
# PARÂMETROS
#########################
DOMINIOS_STRING="$1"
IP="$2"
CLOUDFLARE_KEY="$3"
CLOUDFLARE_EMAIL="$4"
MEUIP="$5"

# Validação
if [ -z "$DOMINIOS_STRING" ] || [ -z "$IP" ] || [ -z "$CLOUDFLARE_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ] || [ -z "$MEUIP" ]; then
    echo "ERRO: Parâmetros insuficientes!"
    echo ""
    echo "Uso: sudo bash installpmta_mult.sh \"dom1|dom2|dom3\" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP"
    echo ""
    echo "Exemplo:"
    echo "  sudo bash installpmta_mult.sh \"mx.teste.com|mail.teste.com\" \"203.0.113.10\" \"cloudflare_key\" \"email@teste.com\" \"198.51.100.50\""
    exit 1
fi

# Converte string em array
IFS='|' read -ra DOMINIOS <<< "$DOMINIOS_STRING"

# Validação
if [ ${#DOMINIOS[@]} -eq 0 ]; then
    echo "ERRO: Nenhum domínio fornecido!"
    exit 1
fi

# Domínio principal (primeiro = PTR/HELO)
DOMINIO_PRINCIPAL="${DOMINIOS[0]}"
ZONA_ROOT=$(echo "$DOMINIO_PRINCIPAL" | rev | cut -d'.' -f1-2 | rev)

# Altera hostname
hostnamectl set-hostname "$DOMINIO_PRINCIPAL"

# Exibe parâmetros
echo "=========================================="
echo "   PARÂMETROS RECEBIDOS"
echo "=========================================="
echo "IP: $IP"
echo "Domínio PTR/HELO: $DOMINIO_PRINCIPAL"
echo "Zona Cloudflare: $ZONA_ROOT"
echo "Total de Domínios: ${#DOMINIOS[@]}"
echo ""
echo "Domínios:"
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
# FUNÇÕES
#########################

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
            echo "DNS temporário configurado."
            break
        else
            echo "Aguardando DNS... Tentativa $((count + 1)) de $max_attempts"
            sleep 1
            ((count++))
            if [ $count -ge $max_attempts ]; then
                echo "Erro ao configurar DNS. Abortando."
                exit 1
            fi
        fi
    done
}

instalar_dependencias() {
    echo "Instalando Dependencias..."
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

# ═══════════════════════════════════════════════════════════
# CORREÇÃO CRÍTICA: Gera DKIM no formato correto (PKCS#1)
# ═══════════════════════════════════════════════════════════
gerar_dkim() {
    local dominio=$1
    local key_file="/etc/pmta/dkim_${dominio}.key"
    local pub_file="/tmp/dkim_${dominio}_pub.pem"
    
    echo "Gerando DKIM para $dominio..." >&2
    
    # CORREÇÃO: usa genrsa ao invés de genpkey
    openssl genrsa -out "$key_file" 2048 2>/dev/null
    
    # Extrai chave pública
    openssl rsa -in "$key_file" -pubout -out "$pub_file" 2>/dev/null
    
    # Permissões
    chown root:pmta "$key_file"
    chmod 640 "$key_file"
    
    # Extrai Base64 limpo
    pubkey=$(grep -v "BEGIN PUBLIC KEY" "$pub_file" | grep -v "END PUBLIC KEY" | tr -d '\n' | tr -d ' ')
    
    # Remove temporário
    rm -f "$pub_file"
    
    echo "$pubkey"
}

# ═══════════════════════════════════════════════════════════
# CORREÇÃO CRÍTICA: Gera TODAS as chaves ANTES de configurar PMTA
# ═══════════════════════════════════════════════════════════
gerar_todas_chaves_dkim() {
    echo "=========================================="
    echo "   GERANDO CHAVES DKIM"
    echo "=========================================="
    
    # Array associativo para armazenar chaves públicas
    declare -g -A DKIM_PUBKEYS
    
    for dominio in "${DOMINIOS[@]}"; do
        pubkey=$(gerar_dkim "$dominio")
        DKIM_PUBKEYS["$dominio"]="$pubkey"
        echo "DEBUG: Armazenado ${dominio}: ${#DKIM_PUBKEYS[$dominio]} chars"
        echo "✓ DKIM gerado: $dominio"
    done
    
    echo "=========================================="
    echo ""
}

configurar_pmta() {
    echo "Configurando PowerMTA..."
    
    # Inicia config
    cat > /etc/pmta/config <<EOF
# Pickup (sem SMTP)
pickup /var/spool/pmta/pickup /var/spool/pmta/badmail

# HTTP Management
http-mgmt-port 1983
http-access 127.0.0.1 admin
http-access $MEUIP admin
http-access $IP admin
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

# Virtual MTA Pool
<virtual-mta-pool pmta-pool>
EOF
    
    # Adiciona cada VMTA no pool
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        echo "    virtual-mta vmta-${vmta_name}" >> /etc/pmta/config
    done
    
    echo "</virtual-mta-pool>" >> /etc/pmta/config
    echo "" >> /etc/pmta/config
    
    # Cria cada Virtual-MTA (agora as chaves JÁ EXISTEM)
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        local dkim_key="/etc/pmta/dkim_${dominio}.key"
        
        # Verifica se a chave existe
        if [ ! -f "$dkim_key" ]; then
            echo "AVISO: Chave DKIM não encontrada para $dominio"
            continue
        fi
        
        cat >> /etc/pmta/config <<EOF
# Virtual MTA: $dominio
<virtual-mta vmta-${vmta_name}>
    smtp-source-host $IP $DOMINIO_PRINCIPAL
    domain-key default,${dominio},${dkim_key}
</virtual-mta>

EOF
    done
    
    # Anexa o config original (com backoff rules, bounce rules, etc)
    if [ -f "config" ]; then
        cat config >> /etc/pmta/config
    fi
    
    chown root:pmta /etc/pmta/config
}

configurar_dns() {
    echo "Configurando DNS na Cloudflare..."
    
    # Obtém zone ID
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
            --data '{"type":"A","name":"'"$subdominio"'","content":"'"$IP"'","ttl":1,"proxied":false}' >/dev/null
        echo "  ✓ A record"
        sleep 2
        
        # MX record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"MX","name":"'"$subdominio"'","content":"'"$dominio"'","ttl":1,"priority":10,"proxied":false}' >/dev/null
        echo "  ✓ MX record"
        sleep 2
        
        # SPF
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"'"$subdominio"'","content":"v=spf1 +a +mx +ip4:'"$IP"' ~all","ttl":1,"proxied":false}' >/dev/null
        echo "  ✓ SPF"
        sleep 2
        
        # DKIM (usa chave já gerada anteriormente)
        pubkey="${DKIM_PUBKEYS[$dominio]}"
        echo "DEBUG: Resgatando ${dominio}: ${#pubkey} chars - Conteúdo: ${pubkey:0:60}..."
        
        if [ -z "$pubkey" ]; then
            echo "  ✗ DKIM - Chave pública não encontrada!"
            continue
        fi
        
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"default._domainkey.'"$dominio"'","content":"v=DKIM1; k=rsa; p='"$pubkey"'","ttl":1,"proxied":false}' 
        echo "  ✓ DKIM (selector: default)"
        sleep 2
        
        # DMARC
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"_dmarc.'"$subdominio"'","content":"v=DMARC1; p=none","ttl":1,"proxied":false}' >/dev/null
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
    
    if [ -f "./cliente" ]; then
        chmod +x ./cliente
    fi
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
    log_message "ERRO: $CLIENTE_CMD não encontrado"
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
    if [ ! -f "./cliente" ]; then
        echo "Binário 'cliente' não encontrado. Pulando monitor."
        return 0
    fi
    
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
    sleep 3
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
    echo ""
    echo "Domínios configurados (${#DOMINIOS[@]}):"
    for dominio in "${DOMINIOS[@]}"; do
        echo "  ✓ $dominio"
    done
    echo ""
    echo "Painel: http://$IP:1983"
    echo "Pickup: /var/spool/pmta/pickup"
    echo ""
    echo "=========================================="
    echo "         PRÓXIMOS PASSOS"
    echo "=========================================="
    echo "1. CRITICAL: Configure PTR no provedor"
    echo "   PTR: $IP → $DOMINIO_PRINCIPAL"
    echo ""
    echo "2. Aguarde propagação DNS (5-15min)"
    echo ""
    echo "3. Teste DKIM:"
    for dominio in "${DOMINIOS[@]}"; do
        echo "   dig TXT default._domainkey.$dominio"
    done
    echo ""
    echo "4. Teste o envio com pickup"
    echo ""
    echo "=========================================="
}

#########################
# EXECUÇÃO (ORDEM CORRIGIDA)
#########################
configurar_dns_temp
instalar_dependencias
instalar_pmta
gerar_todas_chaves_dkim  # ← NOVO: Gera DKIM ANTES do config PMTA
configurar_pmta          # ← Agora as chaves já existem
configurar_dns           # ← Usa chaves já geradas
pickup_config
configurar_firewall
reiniciar_servicos
configure_bash_monitor
start_monitor
exibir_info

# Auto-delete
rm -- "$0"
