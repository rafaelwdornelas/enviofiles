#!/bin/bash
#===============================================================================
# installpmta_mult.sh
# Script de instalação PowerMTA 5.0r3 com suporte a múltiplos domínios
# Cada domínio usa sua VMTA específica com rotação via pool
#
# Uso:
#   sudo bash installpmta_mult.sh "dom1|dom2|dom3" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP
#
# Autor: InstaladorPMTAMultDomains
# Versão: 2.0 (Multi-Domínio com PowerMTA 5.0r3)
#===============================================================================

set -e  # Exit on error

#===============================================================================
# CONFIGURAÇÃO
#===============================================================================

DOMINIOS_STRING="$1"
IP="$2"
CLOUDFLARE_KEY="$3"
CLOUDFLARE_EMAIL="$4"
MEUIP="$5"

PMTA_DIR="/etc/pmta"
CONFIG_FILE="${PMTA_DIR}/config"
LICENSE_FILE="${PMTA_DIR}/license"

LOG_FILE="/var/log/pmta_install.log"

#===============================================================================
# FUNÇÕES AUXILIARES
#===============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    echo "[ERROR] $*" >&2 | tee -a "$LOG_FILE"
    exit 1
}

#===============================================================================
# VALIDAÇÃO DE PARÂMETROS
#===============================================================================

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
    error "Nenhum domínio fornecido!"
fi

# Domínio principal (primeiro = PTR/HELO)
DOMINIO_PRINCIPAL="${DOMINIOS[0]}"
ZONA_ROOT=$(echo "$DOMINIO_PRINCIPAL" | rev | cut -d'.' -f1-2 | rev)

#===============================================================================
# EXIBIR PARÂMETROS
#===============================================================================

log "=========================================="
log "   INSTALAÇÃO POWERMTA MULTI-DOMÍNIO"
log "=========================================="
log "IP: $IP"
log "Domínio PTR/HELO: $DOMINIO_PRINCIPAL"
log "Zona Cloudflare: $ZONA_ROOT"
log "Total de Domínios: ${#DOMINIOS[@]}"
log "IP de Controle: $MEUIP"
log ""
log "Domínios:"
for i in "${!DOMINIOS[@]}"; do
    if [ $i -eq 0 ]; then
        log "  $((i+1)). ${DOMINIOS[$i]} (PTR/HELO)"
    else
        log "  $((i+1)). ${DOMINIOS[$i]}"
    fi
done
log "=========================================="
log ""

#===============================================================================
# FUNÇÕES DE INSTALAÇÃO
#===============================================================================

configurar_dns_temp() {
    log "Configurando DNS temporário..."
    sudo tee /etc/resolv.conf > /dev/null <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

    count=0
    max_attempts=30

    while true; do
        if grep -q "nameserver 8.8.8.8" /etc/resolv.conf && grep -q "nameserver 1.1.1.1" /etc/resolv.conf; then
            log "✓ DNS temporário configurado"
            break
        else
            log "Aguardando DNS... Tentativa $((count + 1)) de $max_attempts"
            sleep 1
            ((count++))
            if [ $count -ge $max_attempts ]; then
                error "Erro ao configurar DNS. Abortando."
            fi
        fi
    done
}

configurar_hostname() {
    log "Configurando hostname do servidor..."
    hostnamectl set-hostname "$DOMINIO_PRINCIPAL"

    # Atualiza /etc/hosts
    if ! grep -q "$DOMINIO_PRINCIPAL" /etc/hosts; then
        echo "$IP $DOMINIO_PRINCIPAL" >> /etc/hosts
    fi

    log "✓ Hostname configurado: $(hostname)"
}

instalar_dependencias() {
    log "Instalando dependências..."

    PKGS_BASE=(unzip openssl curl firewalld)
    PKGS_PERL=(perl perl-core perl-File-Temp perl-Getopt-Long perl-Storable perl-Time-Local)
    PKGS_PMTA=(initscripts libcap)

    if command -v dnf &>/dev/null; then
        MGR=dnf
    elif command -v yum &>/dev/null; then
        MGR=yum
    else
        error "Gerenciador de pacotes não suportado (precisa dnf ou yum)"
    fi

    log "Usando gerenciador: $MGR"

    if [ "$MGR" = "dnf" ]; then
        sudo tee /etc/dnf/dnf.conf > /dev/null <<EOF
[main]
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=True
best=True
skip_if_unavailable=True
fastestmirror=True
max_parallel_downloads=10
deltarpm=True
timeout=30
retries=5
ip_resolve=4
EOF

        sudo dnf clean all -q
        sudo dnf install -y --setopt=retries=5 --setopt=timeout=30 \
            "${PKGS_BASE[@]}" "${PKGS_PERL[@]}" "${PKGS_PMTA[@]}" 2>&1 | grep -v "already installed" || true
    else
        sudo yum install -y yum-plugin-fastestmirror &>/dev/null || true
        sudo yum clean all -q
        sudo yum install -y --skip-broken \
            "${PKGS_BASE[@]}" "${PKGS_PERL[@]}" "${PKGS_PMTA[@]}"
    fi

    sudo mkdir -p /etc/rc.d/rc{0..6}.d
    log "✓ Dependências instaladas"
}

instalar_pmta() {
    log "Baixando PowerMTA 5.0r3..."

    PMTA_URL="http://31.220.76.167/pmta5r3.zip"
    PMTA_ZIP="/tmp/pmta5r3.zip"
    PMTA_EXTRACT_DIR="/tmp/pmta5r3"

    curl -L -o "$PMTA_ZIP" "$PMTA_URL" || error "Falha ao baixar PowerMTA"

    log "Extraindo PowerMTA..."
    rm -rf "$PMTA_EXTRACT_DIR"
    unzip -o "$PMTA_ZIP" -d "$PMTA_EXTRACT_DIR" || error "Falha ao extrair PowerMTA"

    log "Instalando RPMs do PowerMTA..."
    cd "$PMTA_EXTRACT_DIR" || error "Falha ao acessar diretório de extração"

    rpm -ivh PowerMTA-5.0r3.rpm 2>&1 | grep -v "already installed" || true

    # Para serviços
    service pmta stop 2>/dev/null || true
    service pmtahttp stop 2>/dev/null || true

    # Substitui binários patchados
    log "Substituindo binários pelos patchados..."
    rm -rf /usr/sbin/pmtad /usr/sbin/pmtahttpd

    if [ -d "patch/usr/sbin" ]; then
        cp patch/usr/sbin/* /usr/sbin/
    elif [ -d "usr/sbin" ]; then
        cp usr/sbin/* /usr/sbin/
    else
        error "Binários não encontrados em patch/usr/sbin ou usr/sbin"
    fi

    chmod -R 777 /usr/sbin/pmta /usr/sbin/pmtad /usr/sbin/pmtahttpd

    # Copia licença do ZIP
    if [ -f "patch/etc/pmta/license" ]; then
        log "Copiando licença do pacote PowerMTA (patch)..."
        cp patch/etc/pmta/license /etc/pmta/
        chown root:pmta /etc/pmta/license
        chmod 640 /etc/pmta/license
    elif [ -f "license" ]; then
        log "Copiando licença do pacote PowerMTA (raiz)..."
        cp license /etc/pmta/
        chown root:pmta /etc/pmta/license
        chmod 640 /etc/pmta/license
    fi

    # Copia config base para /tmp ANTES de deletar (será usado depois)
    if [ -f "patch/etc/pmta/config" ]; then
        log "Preservando config base do patch..."
        cp "patch/etc/pmta/config" /tmp/pmta_config_base.txt
    elif [ -f "config" ]; then
        log "Preservando config base..."
        cp "config" /tmp/pmta_config_base.txt
    fi

    # Copia cliente para /tmp ANTES de deletar (será usado depois)
    if [ -f "cliente" ]; then
        log "Preservando binário cliente..."
        cp "cliente" /tmp/cliente
        chmod +x /tmp/cliente
    fi

    # Volta para diretório anterior
    cd - > /dev/null

    # Remove config antigo
    rm -rf /etc/pmta/config

    # Limpeza
    rm -rf "$PMTA_ZIP" "$PMTA_EXTRACT_DIR"

    log "✓ PowerMTA instalado com sucesso"
}

#===============================================================================
# GERAÇÃO DE CHAVES DKIM
#===============================================================================

gerar_dkim() {
    local dominio=$1
    local key_file="/etc/pmta/dkim_${dominio}.key"
    local pub_file="/tmp/dkim_${dominio}_pub.pem"

    # Gera chave RSA 2048 bits (formato PKCS#1, compatível com PowerMTA)
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

gerar_todas_chaves_dkim() {
    log "=========================================="
    log "   GERANDO CHAVES DKIM"
    log "=========================================="

    # Array associativo para armazenar chaves públicas
    declare -g -A DKIM_PUBKEYS

    for dominio in "${DOMINIOS[@]}"; do
        pubkey=$(gerar_dkim "$dominio")
        DKIM_PUBKEYS["$dominio"]="$pubkey"
        log "✓ DKIM gerado: $dominio"
    done

    log "=========================================="
    log ""
}

#===============================================================================
# CONFIGURAÇÃO DO POWERMTA
#===============================================================================

configurar_pmta() {
    log "Criando configuração PowerMTA..."

    # Inicia config principal
    cat > "$CONFIG_FILE" <<EOF
# PowerMTA Multi-Domínio Configuration
# Gerado automaticamente por InstaladorPMTAMultDomains
# Arquitetura: 1 IP → Múltiplos Domínios → Pool de VMTAs
# Versão: PowerMTA 5.0r3

# Pickup directory
pickup /var/spool/pmta/pickup /var/spool/pmta/badmail

# SMTP Listener (porta 25 ATIVA para receber bounces externos)
<smtp-listener 0.0.0.0:25>
</smtp-listener>

# HTTP Management API
http-mgmt-port 1983
http-access 127.0.0.1 admin
http-access $MEUIP admin
http-access $IP admin
http-access 0/0 monitor

# Source localhost (API injection)
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

# ============================================
# VIRTUAL MTA POOL - Rotação de Domínios
# ============================================
<virtual-mta-pool pmta-pool>
EOF

    # Adiciona cada VMTA no pool
    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        echo "    virtual-mta vmta-${vmta_name}" >> "$CONFIG_FILE"
    done

    echo "</virtual-mta-pool>" >> "$CONFIG_FILE"
    echo "" >> "$CONFIG_FILE"

    # ========== CONFIGURAÇÕES INDIVIDUAIS DE VMTA ==========

    log "Criando configurações de VMTAs..."

    for dominio in "${DOMINIOS[@]}"; do
        local vmta_name=$(echo "$dominio" | tr '.' '-')
        local dkim_key="/etc/pmta/dkim_${dominio}.key"

        # Verifica se a chave existe
        if [ ! -f "$dkim_key" ]; then
            log "AVISO: Chave DKIM não encontrada para $dominio"
            continue
        fi

        cat >> "$CONFIG_FILE" <<EOF
# Virtual MTA: $dominio
<virtual-mta vmta-${vmta_name}>
    smtp-source-host $IP $DOMINIO_PRINCIPAL
    domain-key default,${dominio},${dkim_key}
</virtual-mta>

EOF
    done

    # ========== RELAY DOMAINS PARA RECEBER BOUNCES ==========

    log "Configurando relay-domains para receber bounces externos..."

    cat >> "$CONFIG_FILE" <<'EOF_RELAY'

# ============================================
# RELAY DOMAINS - RECEBE BOUNCES EXTERNOS
# Permite que todos os domínios recebam
# respostas (bounces) de servidores externos
# ============================================

EOF_RELAY

    # Adiciona relay-domain para CADA domínio
    for dominio in "${DOMINIOS[@]}"; do
        echo "relay-domain $dominio" >> "$CONFIG_FILE"
    done

    echo "" >> "$CONFIG_FILE"

    # Accounting file para remote bounces
    cat >> "$CONFIG_FILE" <<'EOF_ACCT_BOUNCES'
# Accounting para remote bounces (rb)
<acct-file /var/log/pmta/bounces/bouncelog.csv>
    records rb
    record-fields rb timeLogged,orig,rcpt,dsnStatus,dsnDiag,dsnMta,bounceCat,srcType
    world-readable yes
</acct-file>

EOF_ACCT_BOUNCES

    # ========== ANEXA CONFIG BASE (ISP RULES, BACKOFF) ==========

    if [ -f "/tmp/pmta_config_base.txt" ]; then
        log "Anexando configuração base (ISP rules, backoff patterns)..."

        # Processa o config base para substituir placeholders por valores fixos (1 IP)
        # E já remove linhas que não queremos (pickup duplicado, total-max-smtp-out)
        sed -e 's/__TOTAL_MAX_SMTP_OUT__/20/g' \
            -e 's/__HOTMAIL_LIMIT__/250/g' \
            -e 's/__HOTMAIL_BACKOFF__/25/g' \
            -e 's/__YAHOO_LIMIT__/250/g' \
            -e 's/__YAHOO_BACKOFF__/25/g' \
            -e 's/__AOL_LIMIT__/250/g' \
            -e 's/__AOL_BACKOFF__/25/g' \
            -e 's/__GMAIL_LIMIT__/250/g' \
            -e 's/__GMAIL_BACKOFF__/25/g' \
            -e 's/__DEFAULT_LIMIT__/1500/g' \
            -e 's/__DEFAULT_BACKOFF__/500/g' \
            -e 's/__LOCAWEB_LIMIT__/500/g' \
            -e 's/__LOCAWEB_BACKOFF__/100/g' \
            -e 's/__KINGUNIT_LIMIT__/500/g' \
            -e 's/__KINGUNIT_BACKOFF__/100/g' \
            -e 's/__KINGHOST_LIMIT__/500/g' \
            -e 's/__KINGHOST_BACKOFF__/100/g' \
            -e 's/__UMBLER_LIMIT__/500/g' \
            -e 's/__UMBLER_BACKOFF__/100/g' \
            -e 's/__HOSTINGER_LIMIT__/500/g' \
            -e 's/__HOSTINGER_BACKOFF__/100/g' \
            -e 's/__UOLHOST_LIMIT__/500/g' \
            -e 's/__UOLHOST_BACKOFF__/100/g' \
            -e 's/__MESSAGELABS_LIMIT__/500/g' \
            -e 's/__MESSAGELABS_BACKOFF__/100/g' \
            -e 's/__TRENDMICRO_LIMIT__/500/g' \
            -e 's/__TRENDMICRO_BACKOFF__/100/g' \
            -e 's/__APIS_LIMIT__/500/g' \
            -e 's/__APIS_BACKOFF__/100/g' \
            -e 's/__YAHOODNS_LIMIT__/300/g' \
            -e 's/__YAHOODNS_BACKOFF__/60/g' \
            -e 's/__MLICLOUD_LIMIT__/200/g' \
            -e 's/__MLICLOUD_BACKOFF__/40/g' \
            -e 's/__SKYMAIL_LIMIT__/200/g' \
            -e 's/__SKYMAIL_BACKOFF__/40/g' \
            -e 's/__LANIWAY_LIMIT__/200/g' \
            -e 's/__LANIWAY_BACKOFF__/40/g' \
            -e 's/__LEXXA_LIMIT__/200/g' \
            -e 's/__LEXXA_BACKOFF__/40/g' \
            -e 's/__MXSERVER_LIMIT__/200/g' \
            -e 's/__MXSERVER_BACKOFF__/40/g' \
            -e 's/__UOL_LIMIT__/100/g' \
            -e 's/__UOL_BACKOFF__/10/g' \
            -e 's/__TERRA_LIMIT__/150/g' \
            -e 's/__TERRA_BACKOFF__/15/g' \
            -e 's/__BOL_LIMIT__/200/g' \
            -e 's/__BOL_BACKOFF__/20/g' \
            -e 's/__IG_LIMIT__/200/g' \
            -e 's/__IG_BACKOFF__/20/g' \
            -e 's/__GLOBO_LIMIT__/200/g' \
            -e 's/__GLOBO_BACKOFF__/20/g' \
            -e 's/__R7_LIMIT__/200/g' \
            -e 's/__R7_BACKOFF__/20/g' \
            -e 's/__OI_LIMIT__/200/g' \
            -e 's/__OI_BACKOFF__/20/g' \
            -e 's/__ZIPMAIL_LIMIT__/200/g' \
            -e 's/__ZIPMAIL_BACKOFF__/20/g' \
            -e 's/__LINKBR_LIMIT__/200/g' \
            -e 's/__LINKBR_BACKOFF__/20/g' \
            -e '/^pickup /d' \
            -e '/^total-max-smtp-out/d' \
            /tmp/pmta_config_base.txt >> "$CONFIG_FILE"

        log "✓ Configuração base anexada"
    else
        log "⚠ Config base não encontrado, usando configuração mínima"

        # Config mínimo se não encontrar o config base
        cat >> "$CONFIG_FILE" <<'EOF_MIN'
# Configuração base mínima

<domain *>
    max-smtp-out 2
    max-msg-per-connection 5
    max-errors-per-connection 5
    max-msg-rate 1500/h

    connect-timeout 30s
    smtp-greeting-timeout 1m
    data-send-timeout 1m
    smtp-data-termination-timeout 2m

    retry-after 5m
    bounce-after 12h

    backoff-max-msg-rate 500/h
    backoff-retry-after 10m
    backoff-to-normal-after-delivery yes
    backoff-to-normal-after 30m

    use-starttls yes
    dkim-sign yes

    bounce-upon-no-mx yes
    bounce-upon-transfer-failure yes
    mx-connection-attempts 1
</domain>

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
    records d,b
    max-size 10M
</acct-file>

<acct-file /var/log/pmta/diag.csv>
    records t
    max-size 10M
</acct-file>

<spool /var/spool/pmta>
    min-free-space 5G
</spool>
EOF_MIN
    fi

    # Permissões
    chown root:pmta "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"

    log "✓ Configuração PowerMTA criada em $CONFIG_FILE"
}

#===============================================================================
# CONFIGURAÇÃO DO DNS CLOUDFLARE
#===============================================================================

configurar_dns() {
    log "Configurando DNS na Cloudflare..."

    # Obtém zone ID
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$ZONA_ROOT&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_KEY" \
        -H "Content-Type: application/json")

    zoneid=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$zoneid" ]; then
        log "ERRO: Zone ID não encontrado para $ZONA_ROOT"
        return 1
    fi

    log "Zone ID: $zoneid"

    # Para cada domínio
    for dominio in "${DOMINIOS[@]}"; do
        local subdominio=$(echo "$dominio" | sed "s/\.$ZONA_ROOT//")

        log "Configurando DNS para: $dominio"

        # A record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"A","name":"'"$subdominio"'","content":"'"$IP"'","ttl":1,"proxied":false}' >/dev/null
        log "  ✓ A record"
        sleep 2

        # MX record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"MX","name":"'"$subdominio"'","content":"'"$dominio"'","ttl":1,"priority":10,"proxied":false}' >/dev/null
        log "  ✓ MX record"
        sleep 2

        # SPF
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"'"$subdominio"'","content":"v=spf1 +a +mx +ip4:'"$IP"' ~all","ttl":1,"proxied":false}' >/dev/null
        log "  ✓ SPF"
        sleep 2

        # DKIM (usa chave já gerada anteriormente)
        pubkey="${DKIM_PUBKEYS[$dominio]}"

        if [ -z "$pubkey" ]; then
            log "  ✗ DKIM - Chave pública não encontrada!"
            continue
        fi

        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"default._domainkey.'"$dominio"'","content":"v=DKIM1; k=rsa; p='"$pubkey"'","ttl":1,"proxied":false}' >/dev/null
        log "  ✓ DKIM (selector: default)"
        sleep 2

        # DMARC
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_KEY" \
            -H "Content-Type: application/json" \
            --data '{"type":"TXT","name":"_dmarc.'"$subdominio"'","content":"v=DMARC1; p=none","ttl":1,"proxied":false}' >/dev/null
        log "  ✓ DMARC"
        sleep 2
    done

    log "✓ DNS configurado para ${#DOMINIOS[@]} domínios"
}

#===============================================================================
# CONFIGURAÇÃO DE DIRETÓRIOS E PERMISSÕES
#===============================================================================

configurar_diretorios() {
    log "Configurando diretórios..."

    # Cria diretórios necessários
    mkdir -p /var/spool/pmta/{pickup,badmail,q,d,stats}
    mkdir -p /var/log/pmta/archive
    mkdir -p /var/log/pmta/bounces

    # Permissões
    chown -R pmta:pmta /var/spool/pmta
    chown -R pmta:pmta /var/log/pmta
    chown -R root:pmta "$PMTA_DIR"
    chmod 755 "$PMTA_DIR"

    log "✓ Diretórios configurados"
}

#===============================================================================
# CONFIGURAÇÃO DO FIREWALL
#===============================================================================

configurar_firewall() {
    log "Configurando firewall..."

    systemctl start firewalld || true
    systemctl enable firewalld || true

    # Porta 25 (SMTP - receber bounces)
    firewall-cmd --permanent --add-port=25/tcp || true

    # Porta 1983 (HTTP Management)
    firewall-cmd --permanent --add-port=1983/tcp || true

    # Porta 5000 (API cliente)
    firewall-cmd --permanent --add-port=5000/tcp || true

    firewall-cmd --reload || true

    log "✓ Firewall configurado (portas 25, 1983, 5000)"
}

#===============================================================================
# CONFIGURAÇÃO DOS SERVIÇOS
#===============================================================================

configurar_servicos() {
    log "Configurando serviços PowerMTA..."

    # Cria serviço systemd para pmtahttpd
    cat > /etc/systemd/system/pmtahttpd.service << 'HTTPD_EOF'
[Unit]
Description=PowerMTA HTTP Management Interface
After=network.target pmta.service
Requires=pmta.service

[Service]
Type=simple
ExecStart=/usr/sbin/pmtahttpd
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
HTTPD_EOF

    # Habilita e inicia serviços
    systemctl daemon-reload
    systemctl enable pmta
    systemctl enable pmtahttpd
    systemctl start pmta
    systemctl start pmtahttpd

    # Aguarda inicialização
    sleep 5

    # Verifica status
    if systemctl is-active --quiet pmta; then
        log "✓ Serviço PowerMTA iniciado com sucesso"
    else
        error "✗ Falha ao iniciar serviço PowerMTA"
    fi

    if systemctl is-active --quiet pmtahttpd; then
        log "✓ Serviço PowerMTA HTTP iniciado com sucesso"
    else
        log "⚠ Serviço PowerMTA HTTP não iniciou (não crítico)"
    fi
}

#===============================================================================
# CONFIGURAÇÃO DO MONITOR DE PROCESSO (cliente)
#===============================================================================

configurar_monitor() {
    log "Configurando monitor de processo cliente..."

    CURRENT_DIR="/root"
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
    log "✓ Monitor de processo criado: $MONITOR_SCRIPT"
}

iniciar_monitor() {
    # Usa cliente que foi preservado em /tmp pela função instalar_pmta()
    CLIENTE_SOURCE="/tmp/cliente"

    if [[ ! -f "$CLIENTE_SOURCE" ]]; then
        log "⚠ Binário 'cliente' não encontrado. Pulando monitor."
        return 0
    fi

    CURRENT_DIR="/root"
    CLIENTE_DEST="$CURRENT_DIR/cliente"

    # Copia cliente para diretório de trabalho
    log "Copiando cliente para $CLIENTE_DEST..."
    cp "$CLIENTE_SOURCE" "$CLIENTE_DEST"
    chmod +x "$CLIENTE_DEST"

    MONITOR_SCRIPT="$CURRENT_DIR/process_monitor.sh"

    log "Iniciando monitor de processo..."
    nohup "$MONITOR_SCRIPT" > /dev/null 2>&1 &
    MONITOR_PID=$!
    echo $MONITOR_PID > "$CURRENT_DIR/process_monitor.pid"
    sleep 3

    if kill -0 $MONITOR_PID 2>/dev/null; then
        log "✓ Monitor rodando (PID: $MONITOR_PID)"
        log "✓ cliente API iniciado na porta 5000"
    else
        log "⚠ Falha ao iniciar monitor"
    fi
}

#===============================================================================
# EXIBIR INFORMAÇÕES FINAIS
#===============================================================================

exibir_info() {
    log ""
    log "=========================================="
    log "       INSTALAÇÃO CONCLUÍDA"
    log "=========================================="
    log ""
    log "IP: $IP"
    log "PTR/HELO: $DOMINIO_PRINCIPAL"
    log ""
    log "Domínios configurados (${#DOMINIOS[@]}):"
    for dominio in "${DOMINIOS[@]}"; do
        log "  ✓ $dominio"
    done
    log ""
    log "Painel: http://$IP:1983"
    log "Pickup: /var/spool/pmta/pickup"
    log "Bounces: /var/log/pmta/bounces/bouncelog.csv"
    log ""
    log "=========================================="
    log "         PRÓXIMOS PASSOS"
    log "=========================================="
    log "1. CRITICAL: Configure PTR no provedor"
    log "   PTR: $IP → $DOMINIO_PRINCIPAL"
    log ""
    log "2. Aguarde propagação DNS (5-15min)"
    log ""
    log "3. Teste DKIM:"
    for dominio in "${DOMINIOS[@]}"; do
        log "   dig TXT default._domainkey.$dominio"
    done
    log ""
    log "4. Verifique status: pmta show queue"
    log "5. Monitore logs: tail -f /var/log/pmta/log"
    log ""
    log "=========================================="
}

#===============================================================================
# FUNÇÃO PRINCIPAL
#===============================================================================

main() {
    configurar_dns_temp
    configurar_hostname
    instalar_dependencias
    instalar_pmta
    gerar_todas_chaves_dkim
    configurar_pmta
    configurar_dns
    configurar_diretorios
    configurar_firewall
    configurar_servicos
    configurar_monitor
    iniciar_monitor
    exibir_info

    # Auto-remove script
    rm -f "$0"
}

# Executa
main "$@"
