#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# Configura o frontend do debconf como noninteractive
echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections

DOMINIO="$1"
CLOUDFLARE="$2"
CLOUDFLARE_EMAIL="$3"

# Exibe paramentros principais
echo "Nome do Domínio: $DOMINIO"
echo "Chave da Cloudflare: $CLOUDFLARE"
echo "Email da Cloudflare: $CLOUDFLARE_EMAIL"

# Função para baixar arquivos
download_file() {
  local url=$1
  local destino=$2

  echo "Baixando $url ..."
  sudo curl -o "$destino" "$url"
  if [ $? -eq 0 ]; then
    echo "Download concluído com sucesso. O arquivo foi salvo como $destino."
  else
    echo "Ocorreu um erro durante o download de $url."
    exit 1
  fi
}

# Função para configurar hostname e hosts
configure_hostname() {
  echo "$DOMINIO" | sudo tee /etc/hostname
  echo "127.0.0.1  $DOMINIO" | sudo tee -a /etc/hosts
  echo "$DOMINIO" | sudo tee /etc/mailname
  sudo hostname "$DOMINIO"
  sudo hostnamectl set-hostname "$DOMINIO"
}

# Função para instalar pacotes
install_packages() {
  sudo apt-get update
  sudo apt-get install -y software-properties-common dnsutils screen unzip bind9 bind9utils bind9-doc apache2 mutt mailutils curl telnet opendkim opendkim-tools

  # Prepara as seleções para instalação não interativa do Postfix
  sudo debconf-set-selections <<<"postfix postfix/main_mailer_type select 'Internet Site'"
  sudo debconf-set-selections <<<"postfix postfix/mailname string $DOMINIO"
  sudo debconf-set-selections <<<"postfix postfix/destinations string '$DOMINIO, localhost.localdomain, localhost'"
  sudo debconf-set-selections <<<"postfix postfix/root_address string 'root@$DOMINIO'"
  sudo debconf-set-selections <<<"postfix postfix/rfc1035_violation boolean false"
  sudo debconf-set-selections <<<"postfix postfix/protocols select all"
  sudo debconf-set-selections <<<"postfix postfix/mailbox_limit string 0"
  sudo debconf-set-selections <<<"postfix postfix/procmail boolean false"
  sudo debconf-set-selections <<<"postfix postfix/mynetworks string '127.0.0.0/8 [::1]/128'"

  # Instala o Postfix de forma não interativa
  sudo apt-get install -y postfix -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

  # Verifica se o Postfix foi instalado corretamente
  if ! command -v postconf &>/dev/null; then
    echo "Erro: Postfix não foi instalado corretamente."
    exit 1
  fi
}

# Função para configurar DNS
configure_dns() {
  # Remove quaisquer configurações de DNS existentes no arquivo resolv.conf
  sudo sed -i '/^nameserver/d' /etc/resolv.conf
  echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
  echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf

  # Pega o dns.txt e adiciona 40 servidores DNS de forma randômica
  shuf -n 40 dns.txt | while read -r line; do
    echo "nameserver $line" | sudo tee -a /etc/resolv.conf
  done

  sudo systemctl restart networking
}

# Função para configurar SSL
configure_ssl() {
  local CNPJ="$1"
  local COMPANY_NAME="$2"
  local DOMAIN="$3"

  sudo mkdir -p /etc/configs/ssl/new/
  sudo openssl genrsa -des3 --passout pass:789456 -out certificado.key 2048

  # Criar CSR usando os dados fornecidos
  sudo openssl req -new -passin pass:789456 -key certificado.key \
    -subj "/C=BR/ST=Sao Paulo/L=Sao Paulo/O=$COMPANY_NAME/OU=TI/CN=$DOMAIN/emailAddress=contato@$DOMAIN/serialNumber=$CNPJ" \
    -out certificado.csr

  # Gerar o certificado
  sudo openssl x509 -req --passin pass:789456 -days 365 -in certificado.csr -signkey certificado.key -out certificado.cer

  # Remover a senha da chave privada
  sudo openssl rsa --passin pass:789456 -in certificado.key -out certificado.key.nopass
  sudo mv -f certificado.key.nopass certificado.key

  # Criar o certificado da Autoridade Certificadora (CA)
  sudo openssl req -new -x509 -extensions v3_ca -passout pass:789456 \
    -subj "/C=BR/ST=Sao Paulo/L=Sao Paulo/O=$COMPANY_NAME/OU=TI/CN=$DOMAIN/emailAddress=contato@$DOMAIN/serialNumber=$CNPJ" \
    -keyout cakey.pem -out cacert.pem -days 3650

  sudo chmod 600 certificado.key cakey.pem
  sudo mv certificado.key certificado.cer cakey.pem cacert.pem /etc/configs/ssl/new/
}

configure_smtp_header_checks() {
  echo "Configurando smtp_header_checks para modificar cabeçalhos de e-mails enviados..."

  # Cria o arquivo de regras smtp_header_checks
  sudo tee /etc/postfix/smtp_header_checks >/dev/null <<EOF
/^Received:/ IGNORE
/^X-Mailer:/ IGNORE
/^User-Agent:/ IGNORE
EOF

  # Compila as regras
  sudo postmap /etc/postfix/smtp_header_checks

  # Adiciona a configuração ao main.cf
  sudo postconf -e "smtp_header_checks=regexp:/etc/postfix/smtp_header_checks"

  echo "Configuração de smtp_header_checks concluída com sucesso."
}

# Função para configurar o Postfix
configure_postfix() {
  echo "postfix postfix/main_mailer_type string 'internet sites'" | sudo debconf-set-selections
  echo "postfix postfix/mailname string $DOMINIO" | sudo debconf-set-selections

  # Configurações principais
  sudo postconf -e "myhostname=$DOMINIO"
  sudo postconf -e "smtp_helo_name = $DOMINIO"
  sudo postconf -e "smtpd_banner=$DOMINIO ESMTP"
  sudo postconf -e 'relayhost='
  sudo postconf -e "biff=no"
  sudo postconf -e "append_dot_mydomain=no"
  sudo postconf -e "readme_directory=no"
  sudo postconf -e "smtpd_sasl_local_domain="
  sudo postconf -e "smtpd_sasl_authenticated_header=no"

  # Configurações TLS
  sudo postconf -e "smtpd_use_tls=yes"
  sudo postconf -e "smtpd_tls_cert_file=/etc/configs/ssl/new/certificado.cer"
  sudo postconf -e "smtpd_tls_key_file=/etc/configs/ssl/new/certificado.key"
  sudo postconf -e "smtpd_tls_CAfile=/etc/configs/ssl/new/cacert.pem"
  sudo postconf -e "smtpd_tls_security_level=may"
  sudo postconf -e "smtp_tls_security_level=may"
  sudo postconf -e "smtpd_tls_auth_only=yes"
  sudo postconf -e "smtpd_tls_session_cache_database=btree:$(postconf -h data_directory)/smtpd_scache"
  sudo postconf -e "smtp_tls_session_cache_database=btree:$(postconf -h data_directory)/smtp_scache"

  # teste de bloqueio locaweb
  # sudo postconf -e "smtp_connection_reuse_time_limit = 300s"
  # sudo postconf -e "smtp_initial_destination_concurrency = 1"
  # sudo postconf -e "initial_destination_concurrency = 1"
  # sudo postconf -e "smtp_destination_rate_delay = 5s"
  # sudo postconf -e "default_destination_concurrency_limit = 2"
  # sudo postconf -e "default_destination_rate_delay = 1s"

  # Configurações de rede
  sudo postconf -e "mydestination=$DOMINIO, localhost"
  sudo postconf -e "mynetworks=127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 172.0.0.0/8 192.168.0.0/16 10.0.0.0/8"

  # Configurações de alias
  # sudo postconf -e default_destination_rate_delay="2m"
  # sudo postconf -e default_destination_concurrency_failed_cohort_limit="10"

  # Configura IPV6 Preferencialmente
  # sudo postconf -e "inet_protocols = ipv4, ipv6"
  # sudo postconf -e "smtp_address_preference = ipv6"
}

# Função para criar chaves DKIM
# Função para criar chaves DKIM
create_dkim_keys() {
  local DOMAIN="$DOMINIO"
  local SELECTOR="$(echo "$DOMAIN" | cut -d'.' -f1)"
  local DKIM_DIR="/etc/opendkim/keys/$DOMAIN"

  # Criar diretório para as chaves DKIM
  sudo mkdir -p "$DKIM_DIR"
  sudo chown opendkim:opendkim "$DKIM_DIR"
  sudo chmod 700 "$DKIM_DIR"

  # Gerar as chaves DKIM
  sudo opendkim-genkey -b 2048 -h rsa-sha256 -r -s "$SELECTOR" -d "$DOMAIN" -D "$DKIM_DIR"

  # Ajustar permissões das chaves
  sudo chown opendkim:opendkim "$DKIM_DIR/$SELECTOR.private"
  sudo chmod 600 "$DKIM_DIR/$SELECTOR.private"

  # Mover a chave pública para um local apropriado
  sudo mv "$DKIM_DIR/$SELECTOR.txt" "$DKIM_DIR/$SELECTOR.public"

  # Configurar KeyTable
  echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:$DKIM_DIR/$SELECTOR.private" | sudo tee /etc/opendkim/key.table

  # Configurar SigningTable
  echo "*@$DOMAIN $SELECTOR._domainkey.$DOMAIN" | sudo tee /etc/opendkim/signing.table

  # Configurar hosts confiáveis
  sudo tee /etc/opendkim/trusted.hosts >/dev/null <<EOF
127.0.0.1
localhost
$DOMAIN
EOF

  # Escrever a configuração completa do OpenDKIM
  sudo tee /etc/opendkim.conf >/dev/null <<EOF
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
PidFile                 /run/opendkim/opendkim.pid
TrustAnchorFile         /usr/share/dns/root.key
UserID                  opendkim
Socket                  inet:12301@localhost
EOF

  # Reiniciar o OpenDKIM
  sudo systemctl restart opendkim

  # Configurar o Postfix para usar o OpenDKIM
  sudo postconf -e "milter_default_action=accept"
  sudo postconf -e "milter_protocol=6"
  sudo postconf -e "smtpd_milters=inet:localhost:12301"
  sudo postconf -e "non_smtpd_milters=inet:localhost:12301"

  # Reiniciar o Postfix
  sudo systemctl restart postfix

  # Extrair a chave pública DKIM
  DKIM_PUBLIC_KEY=$(sudo sed -n '/p=/,/)/p' "$DKIM_DIR/$SELECTOR.public" | tr -d '\n' | sed -E 's/.*p=([^)]*).*/\1/' | tr -d '"')
  # retira espaços em branco
  DKIM_PUBLIC_KEY=$(echo "$DKIM_PUBLIC_KEY" | xargs)
  echo "Chave pública DKIM: $DKIM_PUBLIC_KEY"

  # Salvar a chave pública DKIM em dkim_public.txt
  echo "$DKIM_PUBLIC_KEY" | sudo tee dkim_public.txt
}

# Função principal
main() {
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

  # Remover espaços em branco
  CNPJ=$(echo "$CNPJ" | xargs)
  COMPANY_NAME=$(echo "$COMPANY_NAME" | xargs)

  configure_ssl "$CNPJ" "$COMPANY_NAME" "$DOMINIO"
  configure_postfix
  create_dkim_keys
  configure_smtp_header_checks

  sudo unzip goenvio.zip -d ./ && sudo chmod 777 -R ./goenvio
  sudo ./goenvio DNS $DOMINIO $CLOUDFLARE $CLOUDFLARE_EMAIL
  sudo /etc/init.d/apache2 restart
  sudo /etc/init.d/postfix restart

  sudo screen -A -m -d -S somename ./goenvio &
  echo "INSTALAÇÂO CONCLUIDA"
}

main "$@"
