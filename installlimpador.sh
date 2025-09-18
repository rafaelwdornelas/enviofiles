#!/bin/bash

# Função para baixar arquivos (sempre sobrescreve)
download_file() {
  local url=$1
  local destino=$2

  # Remove arquivo existente se houver
  if [ -f "$destino" ]; then
    echo "Arquivo '$destino' já existe. Removendo..."
    rm -f "$destino"
  fi

  echo "Baixando $url ..."
  curl -o "$destino" "$url"
  if [ $? -eq 0 ]; then
    echo "Download concluído com sucesso. O arquivo foi salvo como $destino."
    return 0
  else
    echo "Ocorreu um erro durante o download de $url."
    return 1
  fi
}

# Função principal
main() {
    # Faz o download (sobrescreve se existir)
    if ! download_file "https://github.com/rafaelwdornelas/enviofiles/raw/refs/heads/main/limpador.zip" "limpador.zip"; then
        echo "Erro no download. Saindo..."
        exit 1
    fi

    # Remove diretório existente se houver
    if [ -d "./limpador" ]; then
        echo "Removendo diretório 'limpador' existente..."
        rm -rf ./limpador
    fi

    # Extrai o arquivo e configura permissões
    echo "Extraindo arquivo..."
    unzip limpador.zip -d ./ && chmod 777 -R ./limpador

    # Executa o programa
    echo "Iniciando o limpador..."
    sudo screen -A -m -d -S somename ./limpador &
}

main "$@"
