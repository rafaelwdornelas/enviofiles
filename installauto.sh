#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export NEEDRESTART_MODE=a

# Configura o frontend do debconf como noninteractive
echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

DOMINIO="$1"
CLOUDFLARE="$2"
CLOUDFLARE_EMAIL="$3"

# ============================================================
# Validação de parâmetros
# ============================================================
validate_params() {
  if [ -z "$DOMINIO" ]; then
    echo "Erro: Domínio não informado."
    echo "Uso: ./installauto.sh <dominio> <cloudflare_api> <cloudflare_email>"
    exit 1
  fi

  echo "============================================================"
  echo "  Instalação Automática do Servidor de Envio"
  echo "============================================================"
  echo "  Domínio: $DOMINIO"
  echo "  Cloudflare API: $CLOUDFLARE"
  echo "  Cloudflare Email: $CLOUDFLARE_EMAIL"
  echo "============================================================"
  echo ""
}

# ============================================================
# Corrigir repositórios para distros EOL (Debian Buster, etc)
# ============================================================
fix_repositories() {
  local CODENAME DISTRO
  CODENAME=$(lsb_release -cs 2>/dev/null || grep VERSION_CODENAME /etc/os-release 2>/dev/null | cut -d= -f2)
  DISTRO=$(lsb_release -is 2>/dev/null || grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2)
  DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')

  if [ -z "$CODENAME" ]; then
    echo "  Não foi possível detectar o codename da distro, pulando correção de repos."
    return
  fi

  # Debian EOL
  local DEBIAN_EOL="buzz rex bo hamm slink potato woody sarge etch lenny squeeze wheezy jessie stretch buster"
  # Ubuntu EOL
  local UBUNTU_EOL="warty hoary breezy dapper edgy feisty gutsy hardy intrepid jaunty karmic lucid maverick natty oneiric precise quantal raring saucy trusty utopic vivid wily xenial yakkety zesty artful bionic cosmic disco eoan groovy hirsute impish kinetic lunar mantic"

  if echo "$DEBIAN_EOL" | grep -qw "$CODENAME"; then
    echo "  Detectado Debian $CODENAME (EOL). Corrigindo repositórios..."

    cat > /etc/apt/sources.list <<EOF
deb http://archive.debian.org/debian/ ${CODENAME} main contrib non-free
deb http://archive.debian.org/debian-security/ ${CODENAME}/updates main contrib non-free
EOF

    cat > /etc/apt/apt.conf.d/99no-check-valid-until <<EOF
Acquire::Check-Valid-Until "false";
EOF

    echo "  Repositórios corrigidos para archive.debian.org"

  elif echo "$UBUNTU_EOL" | grep -qw "$CODENAME"; then
    echo "  Detectado Ubuntu $CODENAME (EOL). Corrigindo repositórios..."

    cat > /etc/apt/sources.list <<EOF
deb http://old-releases.ubuntu.com/ubuntu/ ${CODENAME} main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ ${CODENAME}-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ ${CODENAME}-security main restricted universe multiverse
EOF

    cat > /etc/apt/apt.conf.d/99no-check-valid-until <<EOF
Acquire::Check-Valid-Until "false";
EOF

    echo "  Repositórios corrigidos para old-releases.ubuntu.com"

  else
    echo "  $DISTRO $CODENAME - repositórios OK."
  fi

  # Remover backports descontinuados
  sed -i '/-backports/d' /etc/apt/sources.list 2>/dev/null
  find /etc/apt/sources.list.d/ -name "*.list" -exec sed -i '/-backports/d' {} \; 2>/dev/null
}

# ============================================================
# Funções auxiliares
# ============================================================
download_file() {
  local url=$1
  local destino=$2

  echo "Baixando $url ..."
  curl -sS -o "$destino" "$url"
  if [ $? -eq 0 ]; then
    echo "Download concluído: $destino"
  else
    echo "Erro durante o download de $url."
    exit 1
  fi
}

# ============================================================
# Instalação de pacotes
# ============================================================
install_packages() {
  echo "[1/8] Instalando pacotes..."
  fix_repositories

  # Aguardar liberação do lock do apt (VPS recém-provisionado pode ter apt rodando)
  while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend 2>/dev/null; do
    echo "  Aguardando apt ficar disponível..."
    sleep 3
  done

  apt-get update
  NEEDRESTART_MODE=a apt-get install -y software-properties-common dnsutils screen unzip \
    mutt mailutils curl telnet opendkim opendkim-tools \
    dovecot-core dovecot-imapd dovecot-pop3d \
    libsasl2-modules sasl2-bin apache2 rsyslog

  # Prepara as seleções para instalação não interativa do Postfix
  debconf-set-selections <<<"postfix postfix/main_mailer_type select 'Internet Site'"
  debconf-set-selections <<<"postfix postfix/mailname string $DOMINIO"
  debconf-set-selections <<<"postfix postfix/destinations string '$DOMINIO, localhost.localdomain, localhost'"
  debconf-set-selections <<<"postfix postfix/root_address string 'root@$DOMINIO'"
  debconf-set-selections <<<"postfix postfix/rfc1035_violation boolean false"
  debconf-set-selections <<<"postfix postfix/protocols select all"
  debconf-set-selections <<<"postfix postfix/mailbox_limit string 0"
  debconf-set-selections <<<"postfix postfix/procmail boolean false"
  debconf-set-selections <<<"postfix postfix/mynetworks string '127.0.0.0/8 [::1]/128'"

  # Instala o Postfix de forma não interativa
  NEEDRESTART_MODE=a apt-get install -y postfix -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

  # Verifica se o Postfix foi instalado corretamente
  if ! command -v postconf &>/dev/null; then
    echo "Erro: Postfix não foi instalado corretamente."
    exit 1
  fi
}

# ============================================================
# Configurar hostname
# ============================================================
configure_hostname() {
  echo "[2/8] Configurando hostname..."
  echo "$DOMINIO" | tee /etc/hostname
  echo "127.0.0.1  $DOMINIO" | tee -a /etc/hosts
  echo "$DOMINIO" | tee /etc/mailname
  hostname "$DOMINIO"
  hostnamectl set-hostname "$DOMINIO"
}

# ============================================================
# Configurar DNS (persistente)
# ============================================================
configure_dns() {
  echo "[3/8] Configurando DNS (persistente)..."

  # Desabilitar systemd-resolved se estiver ativo
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    if [ -L /etc/resolv.conf ]; then
      rm -f /etc/resolv.conf
    fi
  fi

  # Desabilitar sobrescrita pelo dhclient
  if [ -d /etc/dhcp/dhclient-enter-hooks.d ]; then
    cat > /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate <<'DHCEOF'
#!/bin/sh
make_resolv_conf() {
  :
}
DHCEOF
    chmod +x /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate
  fi

  # Remover atributo imutável se existir
  chattr -i /etc/resolv.conf 2>/dev/null || true

  # Construir novo resolv.conf
  cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

  # Adicionar 40 DNS randômicos do dns.txt (removendo \r do Windows)
  if [ -f dns.txt ]; then
    tr -d '\r' < dns.txt | shuf -n 40 | while read -r line; do
      [ -n "$line" ] && echo "nameserver $line" >> /etc/resolv.conf
    done
  fi

  # Tornar imutável para não ser sobrescrito
  chattr +i /etc/resolv.conf

  systemctl restart networking 2>/dev/null || true
}

# ============================================================
# Configurar SSL (Let's Encrypt com fallback auto-assinado)
# ============================================================
configure_ssl() {
  echo "[4/8] Configurando SSL..."
  local CNPJ="$1"
  local COMPANY_NAME="$2"
  local DOMAIN="$3"

  SSL_CERT=""
  SSL_KEY=""
  SSL_CA=""

  # Tentar Let's Encrypt primeiro (precisa da porta 80 livre)
  echo "Tentando obter certificado Let's Encrypt para $DOMAIN..."

  # Instalar certbot
  apt-get remove -y certbot 2>/dev/null || true
  if ! command -v snap &>/dev/null; then
    apt-get install -y snapd 2>/dev/null
  fi
  if command -v snap &>/dev/null; then
    systemctl enable --now snapd.socket 2>/dev/null
    sleep 5
    snap install core 2>/dev/null; snap refresh core 2>/dev/null
    snap install --classic certbot 2>/dev/null
    ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null
  fi
  if ! command -v certbot &>/dev/null; then
    apt-get install -y certbot 2>/dev/null
  fi

  # Parar serviços na porta 80
  systemctl stop apache2 2>/dev/null || true
  fuser -k 80/tcp 2>/dev/null || true

  # Tentar ECDSA primeiro, fallback para RSA
  if command -v certbot &>/dev/null; then
    certbot certonly --standalone --non-interactive --agree-tos \
      --key-type ecdsa --elliptic-curve secp384r1 \
      --email "admin@$DOMAIN" \
      -d "$DOMAIN" 2>/dev/null

    if [ $? -ne 0 ] || [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
      echo "  ECDSA falhou, tentando RSA..."
      certbot certonly --standalone --non-interactive --agree-tos \
        --email "admin@$DOMAIN" \
        -d "$DOMAIN" 2>/dev/null
    fi
  fi

  if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "Certificado Let's Encrypt obtido com sucesso!"
    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    SSL_CA="/etc/letsencrypt/live/$DOMAIN/chain.pem"

    # Hook de renovação
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-mail.sh <<'HOOKEOF'
#!/usr/bin/env bash
set -e
systemctl reload postfix || systemctl restart postfix || true
systemctl reload apache2 || systemctl restart apache2 || true
HOOKEOF
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-mail.sh
    echo "  Hook de renovação SSL instalado"
  else
    echo "Let's Encrypt falhou. Gerando certificado auto-assinado..."

    mkdir -p /etc/configs/ssl/new/
    openssl genrsa -des3 --passout pass:789456 -out certificado.key 2048

    openssl req -new -passin pass:789456 -key certificado.key \
      -subj "/C=BR/ST=Sao Paulo/L=Sao Paulo/O=$COMPANY_NAME/OU=TI/CN=$DOMAIN/emailAddress=contato@$DOMAIN/serialNumber=$CNPJ" \
      -out certificado.csr

    openssl x509 -req --passin pass:789456 -days 365 -in certificado.csr -signkey certificado.key -out certificado.cer

    openssl rsa --passin pass:789456 -in certificado.key -out certificado.key.nopass
    mv -f certificado.key.nopass certificado.key

    openssl req -new -x509 -extensions v3_ca -passout pass:789456 \
      -subj "/C=BR/ST=Sao Paulo/L=Sao Paulo/O=$COMPANY_NAME/OU=TI/CN=$DOMAIN/emailAddress=contato@$DOMAIN/serialNumber=$CNPJ" \
      -keyout cakey.pem -out cacert.pem -days 3650

    chmod 600 certificado.key cakey.pem
    mv certificado.key certificado.cer cakey.pem cacert.pem /etc/configs/ssl/new/
    rm -f certificado.csr

    SSL_CERT="/etc/configs/ssl/new/certificado.cer"
    SSL_KEY="/etc/configs/ssl/new/certificado.key"
    SSL_CA="/etc/configs/ssl/new/cacert.pem"
  fi

  export SSL_CERT SSL_KEY SSL_CA
}

# ============================================================
# Configurar header checks (ampliado)
# ============================================================
configure_smtp_header_checks() {
  echo "Configurando smtp_header_checks..."

  tee /etc/postfix/smtp_header_checks >/dev/null <<EOF
/^Received:/ IGNORE
/^X-Mailer:/ IGNORE
/^User-Agent:/ IGNORE
/^X-Originating-IP:/ IGNORE
/^X-PHP-Originating-Script:/ IGNORE
/^X-Authenticated-Sender:/ IGNORE
/^X-Authenticated-User:/ IGNORE
/^X-Original-To:/ IGNORE
/^X-Google-DKIM-Signature:/ IGNORE
/^X-Gm-Message-State:/ IGNORE
/^X-MS-Exchange-/ IGNORE
/^X-MS-Has-Attach:/ IGNORE
/^X-MS-TNEF-Correlator:/ IGNORE
EOF

  postmap /etc/postfix/smtp_header_checks
  postconf -e "smtp_header_checks=regexp:/etc/postfix/smtp_header_checks"
}

# ============================================================
# Configurar master.cf (portas 465, 587, 2525)
# ============================================================
configure_master_cf() {
  echo "  Configurando master.cf com portas adicionais..."

  cp /etc/postfix/master.cf /etc/postfix/master.cf.bak

  # Remover entradas duplicadas se existirem
  sed -i '/^smtps/,/^[^ ]/{ /^[^ ]/!d; /^smtps/d }' /etc/postfix/master.cf
  sed -i '/^submission/,/^[^ ]/{ /^[^ ]/!d; /^submission/d }' /etc/postfix/master.cf
  sed -i '/^2525/,/^[^ ]/{ /^[^ ]/!d; /^2525/d }' /etc/postfix/master.cf

  cat >> /etc/postfix/master.cf <<'MASTEREOF'

# Porta 465 (SMTPS - SSL implícito)
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Porta 587 (Submission - STARTTLS)
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Porta 2525 (Alternativa)
2525      inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/2525
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
MASTEREOF
}

# ============================================================
# Configurar Dovecot (IMAP/POP3 + SASL)
# ============================================================
configure_dovecot() {
  echo "Configurando Dovecot..."

  SMTP_PASSWORD="P@ssw0rdxinf3ctx"

  cat > /etc/dovecot/dovecot.conf <<EOF
# Dovecot config
protocols = imap pop3
listen = *, ::
login_greeting = $DOMINIO ready.

# Includes
!include conf.d/*.conf
!include_try local.conf
EOF

  # 10-auth.conf
  cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
disable_plaintext_auth = no
auth_mechanisms = plain login
!include auth-passwdfile.conf.ext
EOF

  # auth-passwdfile.conf.ext
  cat > /etc/dovecot/conf.d/auth-passwdfile.conf.ext <<EOF
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/mail/vhosts/%d allow_all_users=yes
}
EOF

  # 10-mail.conf
  cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:/var/mail/vhosts/%d/%n
namespace inbox {
  inbox = yes
}
mail_uid = 5000
mail_gid = 5000
mail_privileged_group = vmail
first_valid_uid = 5000
last_valid_uid = 5000
EOF

  # 10-master.conf
  cat > /etc/dovecot/conf.d/10-master.conf <<EOF
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }
  user = dovecot
}

service auth-worker {
  user = vmail
}
EOF

  # 10-ssl.conf
  cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = yes
ssl_cert = <$SSL_CERT
ssl_key = <$SSL_KEY
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
EOF

  # 15-lda.conf
  cat > /etc/dovecot/conf.d/15-lda.conf <<EOF
protocol lda {
  mail_plugins =
}
EOF

  # 20-imap.conf
  cat > /etc/dovecot/conf.d/20-imap.conf <<EOF
protocol imap {
  mail_max_userip_connections = 50
}
EOF

  # 20-pop3.conf
  cat > /etc/dovecot/conf.d/20-pop3.conf <<EOF
protocol pop3 {
  mail_max_userip_connections = 50
  pop3_uidl_format = %08Xu%08Xv
}
EOF

  mkdir -p /var/spool/postfix/private

  # Criar usuário vmail
  id -u vmail &>/dev/null || useradd -r -m -d /var/mail/vhosts -s /usr/sbin/nologin -u 5000 vmail
  mkdir -p "/var/mail/vhosts/$DOMINIO"
  chown -R vmail:vmail /var/mail/vhosts

  # Criar usuários virtuais
  local PASS_HASH
  PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$SMTP_PASSWORD")

  cat > /etc/dovecot/users <<EOF
admin@${DOMINIO}:${PASS_HASH}:5000:5000::/var/mail/vhosts/${DOMINIO}
noreply@${DOMINIO}:${PASS_HASH}:5000:5000::/var/mail/vhosts/${DOMINIO}
EOF

  chmod 600 /etc/dovecot/users
  chown dovecot:dovecot /etc/dovecot/users

  systemctl restart dovecot
}

# ============================================================
# Configurar o Postfix
# ============================================================
configure_postfix() {
  echo "[5/8] Configurando Postfix..."
  echo "postfix postfix/main_mailer_type string 'internet sites'" | debconf-set-selections
  echo "postfix postfix/mailname string $DOMINIO" | debconf-set-selections

  # Configurações principais
  postconf -e "myhostname=$DOMINIO"
  postconf -e "smtp_helo_name = $DOMINIO"
  postconf -e 'smtpd_banner=$myhostname ESMTP'
  postconf -e 'relayhost='
  postconf -e "biff=no"
  postconf -e "append_dot_mydomain=no"
  postconf -e "readme_directory=no"
  postconf -e "smtpd_sasl_local_domain="
  postconf -e "smtpd_sasl_authenticated_header=no"

  # Configurações TLS (recepção)
  postconf -e "smtpd_use_tls=yes"
  postconf -e "smtpd_tls_cert_file=$SSL_CERT"
  postconf -e "smtpd_tls_key_file=$SSL_KEY"
  if [ -n "$SSL_CA" ]; then
    postconf -e "smtpd_tls_CAfile=$SSL_CA"
  fi
  postconf -e "smtpd_tls_security_level=may"
  postconf -e "smtpd_tls_auth_only=yes"
  postconf -e "smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
  postconf -e "smtpd_tls_session_cache_database=btree:/var/lib/postfix/smtpd_scache"

  # Configurações TLS (envio)
  postconf -e "smtp_tls_security_level=may"
  postconf -e "smtp_tls_protocols=!SSLv2,!SSLv3"
  postconf -e "smtp_tls_ciphers=medium"
  postconf -e "smtp_tls_cert_file=$SSL_CERT"
  postconf -e "smtp_tls_key_file=$SSL_KEY"
  postconf -e "smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_scache"
  postconf -e "smtp_tls_loglevel=1"
  postconf -e "smtp_tls_note_starttls_offer=yes"

  # CA certificates para validar TLS de destino
  postconf -e "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt"

  # Desabilitar SMTPUTF8 (pode quebrar assinatura DKIM)
  postconf -e "smtputf8_enable=no"

  # Bounce rápido - desiste cedo de endereços inválidos
  postconf -e "maximal_queue_lifetime = 4h"
  postconf -e "bounce_queue_lifetime = 1h"

  # Connection cache - reutiliza conexões para mesmo destino
  postconf -e "smtp_connection_cache_on_demand = yes"
  postconf -e "smtp_connection_cache_time_limit = 30s"

  # Sempre usar EHLO moderno ao enviar
  postconf -e "smtp_always_send_ehlo=yes"

  # Forçar IPv4 (evita problemas em VPS sem IPv6)
  postconf -e "inet_protocols=ipv4"

  # Configurações de rede
  postconf -e "mydestination=$DOMINIO, localhost"
  postconf -e "mynetworks=127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 172.0.0.0/8 192.168.0.0/16 10.0.0.0/8"

  # SASL via Dovecot
  postconf -e "smtpd_sasl_type=dovecot"
  postconf -e "smtpd_sasl_path=private/auth"
  postconf -e "smtpd_sasl_auth_enable=yes"
  postconf -e "smtpd_sasl_local_domain=\$myhostname"
  postconf -e "smtpd_sasl_security_options=noanonymous"
  postconf -e "smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"

  # Configurar portas adicionais (465, 587, 2525)
  configure_master_cf
}

# ============================================================
# Criar chaves DKIM
# ============================================================
create_dkim_keys() {
  echo "[6/8] Configurando DKIM..."
  local DOMAIN="$DOMINIO"
  local SELECTOR="$(echo "$DOMAIN" | cut -d'.' -f1)"
  local DKIM_DIR="/etc/opendkim/keys/$DOMAIN"

  mkdir -p "$DKIM_DIR"
  chown opendkim:opendkim "$DKIM_DIR"
  chmod 700 "$DKIM_DIR"

  opendkim-genkey -b 2048 -h rsa-sha256 -r -s "$SELECTOR" -d "$DOMAIN" -D "$DKIM_DIR"

  chown opendkim:opendkim "$DKIM_DIR/$SELECTOR.private"
  chmod 600 "$DKIM_DIR/$SELECTOR.private"

  mv "$DKIM_DIR/$SELECTOR.txt" "$DKIM_DIR/$SELECTOR.public"

  echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:$DKIM_DIR/$SELECTOR.private" | tee /etc/opendkim/key.table
  echo "*@$DOMAIN $SELECTOR._domainkey.$DOMAIN" | tee /etc/opendkim/signing.table

  tee /etc/opendkim/trusted.hosts >/dev/null <<EOF
127.0.0.1
localhost
$DOMAIN
EOF

  tee /etc/opendkim.conf >/dev/null <<EOF
Syslog                  yes
UMask                   002
Domain                  $DOMAIN
AutoRestart             yes
AutoRestartRate         10/1h
Mode                    sv
SubDomains              no
OversignHeaders         From
LogWhy                  yes
SyslogSuccess           yes
KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts
InternalHosts           refile:/etc/opendkim/trusted.hosts
Canonicalization        relaxed/relaxed
PidFile                 /run/opendkim/opendkim.pid
TrustAnchorFile         /usr/share/dns/root.key
UserID                  opendkim
Socket                  inet:12301@localhost
EOF

  systemctl restart opendkim

  postconf -e "milter_default_action=accept"
  postconf -e "milter_protocol=6"
  postconf -e "smtpd_milters=inet:localhost:12301"
  postconf -e "non_smtpd_milters=inet:localhost:12301"

  systemctl restart postfix

  # Extrair a chave pública DKIM (remover espaços, tabs, quebras de linha e aspas)
  DKIM_PUBLIC_KEY=$(sed -n '/p=/,/)/p' "$DKIM_DIR/$SELECTOR.public" | tr -d '\n\t "' | sed -E 's/.*p=([^)]*).*/\1/' | tr -d ' ')
  echo "Chave pública DKIM: $DKIM_PUBLIC_KEY"

  echo "$DKIM_PUBLIC_KEY" | tee dkim_public.txt
}

# ============================================================
# Configurar log rotation para mail
# ============================================================
configure_log_rotation() {
  echo "Configurando log rotation..."

  cat > /etc/logrotate.d/mail-custom <<'EOF'
/var/log/mail.log
/var/log/mail.err
/var/log/mail.warn
/var/log/mail.info
{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
EOF
}

# ============================================================
# Configurar rsyslog para mail.log
# ============================================================
configure_rsyslog() {
  echo "Configurando rsyslog para mail.log..."

  # Garantir que rsyslog está logando mail
  if ! grep -q "mail\.\*" /etc/rsyslog.d/50-default.conf 2>/dev/null && \
     ! grep -q "mail\.\*" /etc/rsyslog.conf 2>/dev/null; then
    echo "mail.*  -/var/log/mail.log" >> /etc/rsyslog.d/50-default.conf 2>/dev/null || \
    echo "mail.*  -/var/log/mail.log" >> /etc/rsyslog.conf
  fi

  systemctl restart rsyslog 2>/dev/null || true
}

# ============================================================
# Função principal
# ============================================================
main() {
  validate_params
  install_packages

  download_file "https://raw.githubusercontent.com/rafaelwdornelas/enviofiles/main/dns.txt" "dns.txt"
  download_file "https://raw.githubusercontent.com/rafaelwdornelas/enviofiles/main/empresas.txt" "empresas.txt"
  download_file "https://raw.githubusercontent.com/rafaelwdornelas/enviofiles/main/goenvio.raf" "goenvio.zip"

  configure_hostname
  configure_dns

  # Ler uma linha aleatória do arquivo de dados
  random_line=$(shuf -n 1 empresas.txt)

  # Extrair CNPJ e Nome da Empresa
  IFS='|' read -r CNPJ COMPANY_NAME <<<"$random_line"
  CNPJ=$(echo "$CNPJ" | xargs)
  COMPANY_NAME=$(echo "$COMPANY_NAME" | xargs)

  configure_ssl "$CNPJ" "$COMPANY_NAME" "$DOMINIO"
  configure_dovecot
  configure_postfix
  create_dkim_keys
  configure_smtp_header_checks
  configure_rsyslog
  configure_log_rotation

  # Extrair e executar goenvio
  unzip -o goenvio.zip -d ./ && chmod 777 -R ./goenvio
  ./goenvio DNS $DOMINIO $CLOUDFLARE $CLOUDFLARE_EMAIL
  /etc/init.d/apache2 restart
  /etc/init.d/postfix restart

  screen -A -m -d -S somename ./goenvio &
  echo ""
  echo "============================================================"
  echo "  INSTALAÇÃO CONCLUÍDA"
  echo "============================================================"
  echo "  Domínio: $DOMINIO"
  echo "  SSL: $SSL_CERT"
  echo "============================================================"
}

main "$@"
