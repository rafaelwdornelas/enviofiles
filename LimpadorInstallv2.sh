#!/bin/bash

# Função para verificar e instalar dependências
install_dependencies() {
    echo "Verificando dependências..."
    
    # Lista de pacotes necessários
    local packages_to_install=""
    
    # Verifica se unzip está instalado
    if ! command -v unzip &> /dev/null; then
        echo "unzip não encontrado. Será instalado."
        packages_to_install="$packages_to_install unzip"
    else
        echo "unzip já está instalado."
    fi
    
    # Verifica se screen está instalado
    if ! command -v screen &> /dev/null; then
        echo "screen não encontrado. Será instalado."
        packages_to_install="$packages_to_install screen"
    else
        echo "screen já está instalado."
    fi
    
    # Instala os pacotes necessários se houver algum
    if [ -n "$packages_to_install" ]; then
        echo "Instalando dependências:$packages_to_install"
        
        # Detecta o gerenciador de pacotes
        if command -v apt-get &> /dev/null; then
            echo "Usando apt-get para instalação..."
            sudo apt-get update && sudo apt-get install -y $packages_to_install
        elif command -v yum &> /dev/null; then
            echo "Usando yum para instalação..."
            sudo yum install -y $packages_to_install
        elif command -v dnf &> /dev/null; then
            echo "Usando dnf para instalação..."
            sudo dnf install -y $packages_to_install
        elif command -v pacman &> /dev/null; then
            echo "Usando pacman para instalação..."
            sudo pacman -S --noconfirm $packages_to_install
        elif command -v zypper &> /dev/null; then
            echo "Usando zypper para instalação..."
            sudo zypper install -y $packages_to_install
        else
            echo "Erro: Gerenciador de pacotes não suportado."
            echo "Por favor, instale manualmente: $packages_to_install"
            exit 1
        fi
        
        # Verifica se a instalação foi bem-sucedida
        if [ $? -eq 0 ]; then
            echo "Dependências instaladas com sucesso!"
        else
            echo "Erro na instalação das dependências. Saindo..."
            exit 1
        fi
    else
        echo "Todas as dependências já estão instaladas."
    fi
}

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
    echo "=== Iniciando script de instalação ==="
    
    # Primeiro, instala as dependências necessárias
    install_dependencies
    
    echo "=== Fazendo download do arquivo ==="
    
    # Faz o download (sobrescreve se existir)
    if ! download_file "https://raw.githubusercontent.com/rafaelwdornelas/enviofiles/main/limpador.zip" "limpador.zip"; then
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
    
    echo "=== Script executado com sucesso ==="
}

main "$@"
