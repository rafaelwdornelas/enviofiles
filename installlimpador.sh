#!/bin/bash

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


# Função principal
main() {
    download_file "https://github.com/rafaelwdornelas/enviofiles/raw/refs/heads/main/limpador.zip" "limpador.zip"

    unzip limpador.zip -d ./ && chmod 777 -R ./limpador

    sudo screen -A -m -d -S somename ./limpador &

}