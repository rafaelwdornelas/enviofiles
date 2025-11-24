#!/bin/bash
#===============================================================================
# reconfigpmta_mult.sh
# Script de reconfiguração PowerMTA 5.0r3 com suporte a múltiplos domínios
# Reconfigura servidores já instalados com novos domínios
#
# Uso:
#   sudo bash reconfigpmta_mult.sh "dom1|dom2|dom3" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP
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

LOG_FILE="/var/log/pmta_reconfig.log"

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
    echo "Uso: sudo bash reconfigpmta_mult.sh \"dom1|dom2|dom3\" IP CLOUDFLARE_KEY CLOUDFLARE_EMAIL MEUIP"
    echo ""
    echo "Exemplo:"
    echo "  sudo bash reconfigpmta_mult.sh \"mx.teste.com|mail.teste.com\" \"203.0.113.10\" \"cloudflare_key\" \"email@teste.com\" \"198.51.100.50\""
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
log "   RECONFIGURAÇÃO POWERMTA MULTI-DOMÍNIO"
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
# FUNÇÕES DE RECONFIGURAÇÃO
#===============================================================================

parar_servicos() {
    log "Parando serviços PowerMTA..."
    systemctl stop pmta pmtahttp 2>/dev/null || service pmta stop 2>/dev/null || true
    sleep 2
    log "✓ Serviços parados"
}

limpar_logs() {
    log "Limpando logs do PowerMTA..."
    rm -f /var/log/pmta/log 2>/dev/null || true
    rm -f /var/log/pmta/acct.csv 2>/dev/null || true
    rm -f /var/log/pmta/diag.csv 2>/dev/null || true
    rm -rf /var/log/pmta/bounces/* 2>/dev/null || true
    log "✓ Logs limpos"
}

limpar_fila_e_stats() {
    log "Limpando fila e estatísticas..."
    rm -rf /var/spool/pmta/q/* 2>/dev/null || true
    rm -rf /var/spool/pmta/d/* 2>/dev/null || true
    rm -rf /var/spool/pmta/stats/* 2>/dev/null || true
    rm -f /var/spool/pmta/*.dat 2>/dev/null || true
    log "✓ Fila e estatísticas limpos"
}

deletar_chaves_dkim_antigas() {
    log "Deletando chaves DKIM antigas..."
    rm -f /etc/pmta/dkim_*.key
    log "✓ Chaves DKIM antigas deletadas"
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
    log "Recriando configuração PowerMTA..."

    # Remove config antigo
    rm -f "$CONFIG_FILE"

    # Inicia config principal
    cat > "$CONFIG_FILE" <<EOF
# PowerMTA Multi-Domínio Configuration
# Gerado automaticamente por InstaladorPMTAMultDomains (Reconfiguração)
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
    # Busca o config base que deveria estar preservado em /etc/pmta/config-base
    # ou usa o que está em /tmp se disponível

    CONFIG_BASE_SOURCE=""
    if [ -f "/etc/pmta/config-base" ]; then
        CONFIG_BASE_SOURCE="/etc/pmta/config-base"
    elif [ -f "/tmp/pmta_config_base.txt" ]; then
        CONFIG_BASE_SOURCE="/tmp/pmta_config_base.txt"
    fi

    if [ -n "$CONFIG_BASE_SOURCE" ]; then
        log "Anexando configuração base de $CONFIG_BASE_SOURCE..."

        # Processa o config base para substituir placeholders por valores fixos (1 IP)
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
            "$CONFIG_BASE_SOURCE" >> "$CONFIG_FILE"

        # Remove a linha total-max-smtp-out (não queremos limite global)
        sed -i '/^total-max-smtp-out/d' "$CONFIG_FILE"

        # Remove pickup duplicado (já tem no início)
        sed -i '/^pickup \/var\/spool\/pmta\/pickup/d' "$CONFIG_FILE"

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

    log "✓ Configuração PowerMTA recriada em $CONFIG_FILE"
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
# CONFIGURAÇÃO DE DIRETÓRIOS
#===============================================================================

configurar_diretorios() {
    log "Verificando diretórios..."

    # Garante que diretórios existem
    mkdir -p /var/spool/pmta/{pickup,badmail,q,d,stats}
    mkdir -p /var/log/pmta/archive
    mkdir -p /var/log/pmta/bounces

    # Permissões
    chown -R pmta:pmta /var/spool/pmta
    chown -R pmta:pmta /var/log/pmta
    chown -R root:pmta "$PMTA_DIR"
    chmod 755 "$PMTA_DIR"

    log "✓ Diretórios verificados"
}

#===============================================================================
# REINICIAR SERVIÇOS
#===============================================================================

reiniciar_servicos() {
    log "Reiniciando serviços PowerMTA..."

    systemctl restart pmta
    systemctl restart pmtahttpd

    sleep 5

    # Reload config
    pmta reload 2>/dev/null || true

    # Verifica status
    if systemctl is-active --quiet pmta; then
        log "✓ Serviço PowerMTA reiniciado com sucesso"
    else
        error "✗ Falha ao reiniciar serviço PowerMTA"
    fi

    if systemctl is-active --quiet pmtahttpd; then
        log "✓ Serviço PowerMTA HTTP reiniciado com sucesso"
    else
        log "⚠ Serviço PowerMTA HTTP não reiniciou (não crítico)"
    fi
}

#===============================================================================
# EXIBIR INFORMAÇÕES FINAIS
#===============================================================================

exibir_info() {
    log ""
    log "=========================================="
    log "     RECONFIGURAÇÃO CONCLUÍDA"
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
    parar_servicos
    limpar_logs
    limpar_fila_e_stats
    deletar_chaves_dkim_antigas
    configurar_hostname
    gerar_todas_chaves_dkim
    configurar_pmta
    configurar_dns
    configurar_diretorios
    reiniciar_servicos
    exibir_info

    # Auto-remove script
    rm -f "$0"
}

# Executa
main "$@"
