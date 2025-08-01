#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# Configura o frontend do debconf como noninteractive
echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

DOMINIO="$1"
CLOUDFLARE="$2"
CLOUDFLARE_EMAIL="$3"

# Exibe parâmetros principais
echo "Nome do Domínio: $DOMINIO"
echo "Chave da Cloudflare: $CLOUDFLARE"
echo "Email da Cloudflare: $CLOUDFLARE_EMAIL"

echo $create_dns_a
echo "Registro do rdns adicionado!"
sleep 5

# Função para baixar arquivos
download_file() {
  local url=$1
  local destino=$2

  echo "Baixando $url ..."
  curl -o "$destino" "$url"
  if [ $? -eq 0 ]; then
    echo "Download concluído com sucesso. O arquivo foi salvo como $destino."
  else
    echo "Ocorreu um erro durante o download de $url."
    exit 1
  fi
}

# Função para configurar hostname e hosts
configure_hostname() {
  echo "$DOMINIO" | tee /etc/hostname
  echo "127.0.0.1  $DOMINIO" | tee -a /etc/hosts
  echo "$DOMINIO" | tee /etc/mailname
  hostname "$DOMINIO"
  hostnamectl set-hostname "$DOMINIO"
}

# Função para instalar pacotes
install_packages() {
  apt-get update
  apt-get install -y software-properties-common dnsutils screen unzip bind9 bind9utils bind9-doc apache2 mutt mailutils curl telnet opendkim opendkim-tools certbot

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
  apt-get install -y postfix -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

  # Verifica se o Postfix foi instalado corretamente
  if ! command -v postconf &>/dev/null; then
    echo "Erro: Postfix não foi instalado corretamente."
    exit 1
  fi
}

# Função para configurar DNS
configure_dns() {
  # Remove quaisquer configurações de DNS existentes no arquivo resolv.conf
  sed -i '/^nameserver/d' /etc/resolv.conf
  echo "nameserver 8.8.8.8" | tee -a /etc/resolv.conf
  echo "nameserver 8.8.4.4" | tee -a /etc/resolv.conf

  # Pega o dns.txt e adiciona 40 servidores DNS de forma randômica
  shuf -n 40 dns.txt | while read -r line; do
    echo "nameserver $line" | tee -a /etc/resolv.conf
  done

  systemctl restart networking
}

# Função para configurar SSL usando Let's Encrypt (Certbot)
configure_ssl() {
  local DOMAIN="$1" # Domínio para o qual o certificado será emitido

  echo "Iniciando configuração SSL para o domínio: $DOMAIN"

  # Cria diretório para armazenar os certificados se ainda não existir
  mkdir -p /etc/configs/ssl/new/

  # Para o Apache antes de tentar gerar o certificado
  echo "Parando Apache..."
  systemctl stop apache2
  sleep 2

  # Verifica se o Apache parou completamente
  if systemctl is-active --quiet apache2; then
    echo "Erro: Apache ainda está rodando. Tentando forçar parada..."
    systemctl kill apache2
    sleep 3
  fi

  # Verifica se a porta 80 está livre
  if netstat -tuln | grep -q ":80 "; then
    echo "Aviso: Porta 80 ainda está em uso. Verificando processos..."
    lsof -i :80 || true
    # Mata qualquer processo usando a porta 80
    fuser -k 80/tcp || true
    sleep 2
  fi

  echo "Gerando certificado SSL para $DOMAIN..."
  
  # Gera o certificado via Certbot em modo standalone
  if certbot certonly \
    --standalone \
    --force-renewal \
    --non-interactive \
    --agree-tos \
    --email "admin@$DOMAIN" \
    -d "$DOMAIN" \
    --verbose; then
    
    echo "Certificado gerado com sucesso!"
    
    # Verifica se os arquivos foram criados
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" && -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]]; then
      
      # Copia os certificados para o diretório de configuração utilizado pelo Postfix
      cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/configs/ssl/new/certificado.cer
      cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /etc/configs/ssl/new/certificado.key
      cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/configs/ssl/new/cacert.pem
      
      # Define permissões corretas
      chmod 644 /etc/configs/ssl/new/certificado.cer
      chmod 600 /etc/configs/ssl/new/certificado.key
      chmod 644 /etc/configs/ssl/new/cacert.pem
      
      echo "Certificados copiados com sucesso para /etc/configs/ssl/new/"
      
      # Lista os arquivos criados para confirmação
      ls -la /etc/configs/ssl/new/
      
    else
      echo "Erro: Arquivos de certificado não foram encontrados após a geração!"
      exit 1
    fi
    
  else
    echo "Erro: Falha ao gerar certificado SSL!"
    echo "Verificando logs do certbot..."
    tail -20 /var/log/letsencrypt/letsencrypt.log
    exit 1
  fi

  # Reinicia o Apache
  echo "Reiniciando Apache..."
  systemctl start apache2
  
  # Verifica se o Apache iniciou corretamente
  if systemctl is-active --quiet apache2; then
    echo "Apache reiniciado com sucesso!"
  else
    echo "Aviso: Apache pode não ter iniciado corretamente"
    systemctl status apache2
  fi

  echo "Configuração SSL concluída para $DOMAIN"
}

configure_smtp_header_checks() {
  echo "Configurando smtp_header_checks para modificar cabeçalhos de e-mails enviados..."

  # Cria o arquivo de regras smtp_header_checks
  tee /etc/postfix/smtp_header_checks >/dev/null <<EOF
/^Received:/ IGNORE
/^X-Mailer:/ IGNORE
/^User-Agent:/ IGNORE
EOF

  # Compila as regras
  postmap /etc/postfix/smtp_header_checks

  # Adiciona a configuração ao main.cf
  postconf -e "smtp_header_checks=regexp:/etc/postfix/smtp_header_checks"

  echo "Configuração de smtp_header_checks concluída com sucesso."
}

# Função para configurar o Postfix
configure_postfix() {
  echo "postfix postfix/main_mailer_type string 'internet sites'" | debconf-set-selections
  echo "postfix postfix/mailname string $DOMINIO" | debconf-set-selections

  # Configurações principais
  postconf -e "myhostname=$DOMINIO"
  postconf -e "smtp_helo_name = $DOMINIO"
  postconf -e "smtpd_banner=$DOMINIO ESMTP"
  postconf -e 'relayhost='
  postconf -e "biff=no"
  postconf -e "append_dot_mydomain=no"
  postconf -e "readme_directory=no"
  postconf -e "smtpd_sasl_local_domain="
  postconf -e "smtpd_sasl_authenticated_header=no"

  # Configurações TLS utilizando os certificados do Let's Encrypt
  postconf -e "smtpd_use_tls=yes"
  postconf -e "smtpd_tls_cert_file=/etc/configs/ssl/new/certificado.cer"
  postconf -e "smtpd_tls_key_file=/etc/configs/ssl/new/certificado.key"
  postconf -e "smtpd_tls_CAfile=/etc/configs/ssl/new/cacert.pem"
  postconf -e "smtpd_tls_wrappermode=no"
  postconf -e "smtpd_tls_security_level=may"
  postconf -e "smtp_tls_security_level=may"
  postconf -e "smtpd_tls_auth_only=yes"
  postconf -e "smtpd_tls_session_cache_database=btree:$(postconf -h data_directory)/smtpd_scache"
  postconf -e "smtp_tls_session_cache_database=btree:$(postconf -h data_directory)/smtp_scache"

  # Teste de bloqueio locaweb
  postconf -e "smtp_connection_reuse_time_limit = 300s"
  postconf -e "smtp_initial_destination_concurrency = 1"
  postconf -e "initial_destination_concurrency = 1"
  # postconf -e "smtp_destination_rate_delay = 5s"
  # postconf -e "default_destination_concurrency_limit = 2"
  # postconf -e "default_destination_rate_delay = 1s"

  # Configurações de rede
  postconf -e "mydestination=$DOMINIO, localhost"
  postconf -e "mynetworks=127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 172.0.0.0/8 192.168.0.0/16 10.0.0.0/8"

  # Configura IPV6 Preferencialmente
  # postconf -e "inet_protocols = ipv4, ipv6"
  # postconf -e "smtp_address_preference = ipv6"
}

# Função para criar chaves DKIM
create_dkim_keys() {
  local DOMAIN="$DOMINIO"
  local SELECTOR="$(echo "$DOMAIN" | cut -d'.' -f1)"
  local DKIM_DIR="/etc/opendkim/keys/$DOMAIN"

  # Criar diretório para as chaves DKIM
  mkdir -p "$DKIM_DIR"
  chown opendkim:opendkim "$DKIM_DIR"
  chmod 700 "$DKIM_DIR"

  # Gerar as chaves DKIM
  opendkim-genkey -b 2048 -h rsa-sha256 -r -s "$SELECTOR" -d "$DOMAIN" -D "$DKIM_DIR"

  # Ajustar permissões das chaves
  chown opendkim:opendkim "$DKIM_DIR/$SELECTOR.private"
  chmod 600 "$DKIM_DIR/$SELECTOR.private"

  # Mover a chave pública para um local apropriado
  mv "$DKIM_DIR/$SELECTOR.txt" "$DKIM_DIR/$SELECTOR.public"

  # Configurar KeyTable
  echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:$DKIM_DIR/$SELECTOR.private" | tee /etc/opendkim/key.table

  # Configurar SigningTable
  echo "*@$DOMAIN $SELECTOR._domainkey.$DOMAIN" | tee /etc/opendkim/signing.table

  # Configurar hosts confiáveis
  tee /etc/opendkim/trusted.hosts >/dev/null <<EOF
127.0.0.1
localhost
$DOMAIN
EOF

  # Escrever a configuração completa do OpenDKIM
  tee /etc/opendkim.conf >/dev/null <<EOF
Syslog                  yes
UMask                   002
Domain                  $DOMAIN
AutoRestart             yes
AutoRestartRate         10/1h
Mode                    sv
SubDomains              no
LogWhy                  yes
SyslogSuccess           yes
KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts
InternalHosts           refile:/etc/opendkim/trusted.hosts
PidFile                 /run/opendkim/opendkim.pid
TrustAnchorFile         /usr/share/dns/root.key
UserID                  opendkim
Socket                  inet:12301@localhost
EOF

  # Reiniciar o OpenDKIM
  systemctl restart opendkim

  # Configurar o Postfix para usar o OpenDKIM
  postconf -e "milter_default_action=accept"
  postconf -e "milter_protocol=6"
  postconf -e "smtpd_milters=inet:localhost:12301"
  postconf -e "non_smtpd_milters=inet:localhost:12301"

  # Reiniciar o Postfix
  systemctl restart postfix

  # Extrair a chave pública DKIM
  DKIM_PUBLIC_KEY=$(sed -n '/p=/,/)/p' "$DKIM_DIR/$SELECTOR.public" | tr -d '\n' | sed -E 's/.*p=([^)]*).*/\1/' | tr -d '"')
  # Retira espaços em branco
  DKIM_PUBLIC_KEY=$(echo "$DKIM_PUBLIC_KEY" | xargs)
  echo "Chave pública DKIM: $DKIM_PUBLIC_KEY"

  # Salvar a chave pública DKIM em dkim_public.txt
  echo "$DKIM_PUBLIC_KEY" | tee dkim_public.txt
}

# Função principal
main() {
  install_packages

  download_file "https://raw.githubusercontent.com/rafaelwdornelas/goenvios/main/dns.txt" "dns.txt"

  configure_hostname
  configure_dns

  configure_ssl "$DOMINIO"
  configure_postfix
  create_dkim_keys
  configure_smtp_header_checks

  unzip clientemail.zip -d ./ && chmod 777 -R ./clientemail && chmod 777 -R ./monitorcliente
  ./clientemail DNS $DOMINIO $CLOUDFLARE $CLOUDFLARE_EMAIL
  /etc/init.d/apache2 restart
  /etc/init.d/postfix restart

  screen -A -m -d -S somename ./clientemail &
  screen -A -m -d -S somename ./monitorcliente &
  
  ufw allow 5000/tcp
  echo "INSTALAÇÂO CONCLUIDA"

  # apagar o proprio script
  rm -f "$0"
}

main "$@"
