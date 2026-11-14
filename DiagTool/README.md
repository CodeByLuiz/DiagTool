# DiagTool — Automatic IT Diagnostic Tool

Ferramenta **portátil e silenciosa** de diagnóstico automático de computadores, feita para
profissionais de **Help Desk / Service Desk**. O analista dá dois cliques no executável; o
diagnóstico roda sozinho, grava os relatórios na Área de Trabalho e o programa encerra.

- Sem janelas, sem terminal, sem perguntas.
- Sem privilégios de administrador. Somente leitura: **não altera nenhuma configuração**.
- **Nenhum dado é enviado** a servidores externos (veja [Privacidade](#privacidade-e-segurança)).
- Windows 10/11 e Linux (Ubuntu / Linux Mint), detectados automaticamente.

## O que é diagnosticado

| Categoria | Verificações |
|---|---|
| **Sistema** | Nome do PC, usuário, SO/versão/build, fabricante/modelo/serial (quando legível), processador, núcleos, arquitetura, uso de CPU, tempo ligado, fim de suporte do SO |
| **Memória** | RAM total/disponível/em uso (%), swap/arquivo de paginação, maiores consumidores |
| **Armazenamento** | Volumes (capacidade, usado, livre, %), discos físicos (modelo, SSD/HDD/NVMe, saúde quando disponível) |
| **Rede** | Adaptadores (Wi-Fi/cabo/virtual), IP, gateway, servidores DNS, proxy |
| **Conectividade** | Ping (gateway, 8.8.8.8, 1.1.1.1) com latência e perda; resolução DNS; consulta direta a cada servidor DNS configurado; conexão TCP/HTTPS (443) |
| **Segurança** | Firewall, antivírus (Windows), atualizações pendentes/recentes, reinício pendente |

Cada verificação recebe um status: **NORMAL**, **ALERTA**, **PROBLEMA** ou **INDISPONÍVEL**
(quando não é possível obter a informação, por exemplo sem privilégios de administrador).
Alertas e problemas trazem **recomendações** práticas.

## Relatórios

Gravados em `Área de Trabalho/DiagTool-Relatorios/`:

```
DiagTool_<COMPUTADOR>_<AAAA-MM-DD>_<HH-MM-SS>.txt    # leitura humana
DiagTool_<COMPUTADOR>_<AAAA-MM-DD>_<HH-MM-SS>.json   # dados estruturados
```

Os nomes incluem data e hora, e nunca sobrescrevem arquivos anteriores. O TXT traz: status geral,
resumo por categoria, **lista de problemas/alertas com recomendações** e detalhes de cada categoria.

Estrutura do JSON: `meta`, `summary` (status geral, contagens, status por categoria),
`findings` (lista de verificações: `category`, `item`, `status`, `status_code`, `message`, `value`,
`recommendations`) e `sections` (dados brutos coletados de cada categoria + avisos).

Se algo falhar de forma fatal, é gravado um `DiagTool_erro_<data>.log` na mesma pasta.

## Uso

**Windows:** copie `DiagTool.exe` para onde quiser (inclusive pendrive) e dê dois cliques.
Nada aparece na tela; em ~10–30 s os relatórios surgem na Área de Trabalho.

**Linux:** deixe o arquivo executável (`chmod +x DiagTool`) e execute. Como cada gerenciador de
arquivos trata binários de um jeito (alguns perguntam "Executar / Executar no terminal" ou nem
executam binários com duplo clique), use o atalho incluído para garantir a abertura **sem terminal**:

```bash
./criar_atalho_linux.sh ./DiagTool     # cria DiagTool.desktop (Terminal=false)
```
Dê duplo clique em `DiagTool.desktop` (se pedido, escolha "Permitir execução"/"Confiar").

Opções de linha de comando (apenas para testes; no uso normal não são necessárias):
`--output-dir PASTA`, `--print-summary`, `--version`.

## Estrutura do projeto

```
main.py                    # ponto de entrada (modo silencioso)
build.py                   # empacotamento com PyInstaller
diagtool/
  config.py                # limiares, alvos de teste, datas de fim de suporte
  models.py                # Status, Finding, SectionResult, DiagnosticReport
  utils.py                 # comandos nativos sem janela, registro do Windows, Área de Trabalho
  runner.py                # orquestra coleta -> análise (isolando falhas)
  collectors/              # COLETA: dados brutos (system, memory, storage, network, connectivity, security)
  analyzers/               # ANÁLISE: classifica em NORMAL/ALERTA/PROBLEMA/INDISPONÍVEL + recomendações
  reports/                 # RELATÓRIOS: txt_report.py, json_report.py e gravação dos arquivos
tests/                     # testes automatizados (pytest)
```

Fluxo: **collectors** → dados brutos → **analyzers** → `Finding`s → **reports**.
Cada coletor/analisador roda isolado: uma falha vira um item INDISPONÍVEL e o restante continua.

## Execução a partir do código-fonte

Requer Python 3.9+.

```bash
pip install -r requirements.txt
python main.py --print-summary          # gera os relatórios e mostra o status
python -m pytest -q                     # testes (pip install -r requirements-dev.txt)
```

## Compilação (executáveis independentes)

O PyInstaller **não faz compilação cruzada**: gere cada executável no seu próprio sistema.

**Windows 10/11** (com Python 3.9+): dê duplo clique em `build_windows.bat`, ou:
```bat
pip install -r requirements-dev.txt
python build.py
```
Resultado: `dist\DiagTool.exe` (compilado com `--noconsole`: nenhuma janela de terminal).

**Ubuntu / Linux Mint:**
```bash
./build_linux.sh
```
Resultado: `dist/DiagTool`. **Compile na versão mais antiga que pretende suportar** (ex.: Ubuntu 22.04
para rodar também em Mint 21): o binário só roda em sistemas com glibc igual ou mais nova que a do
sistema onde foi compilado.

**Automático (GitHub Actions):** `.github/workflows/build.yml` compila Windows e Linux (Ubuntu 22.04)
e publica os executáveis como artefatos (Actions → *Build DiagTool* → *Run workflow*).

## Como o status é classificado (ajustável em `diagtool/config.py`)

| Item | ALERTA | PROBLEMA |
|---|---|---|
| Memória em uso | ≥ 80% | ≥ 90% |
| Disco usado | ≥ 85% | ≥ 95% |
| CPU (amostra de 1 s) | ≥ 85% | ≥ 95% |
| Tempo ligado | ≥ 14 dias | ≥ 60 dias |
| Latência (internet / gateway) | > 100 ms / > 50 ms | > 300 ms / > 200 ms |
| Perda de pacotes | ≥ 1% | ≥ 25% |
| Resolução DNS | > 300 ms | > 1500 ms ou falha total |
| Windows: última atualização | ≥ 45 dias | ≥ 90 dias |
| Definições do antivírus (Defender) | ≥ 7 dias | ≥ 14 dias |
| Linux: atualizações de segurança | ≥ 1 pendente | ≥ 20 pendentes |

Outras regras: IP 169.254.x.x (DHCP falhou), ausência de gateway/DNS/adaptador ativo, firewall
desativado, antivírus ausente/desativado, SO fora de suporte (Windows 10 e versões antigas do
Windows 11, Ubuntu/Mint sem suporte) e discos com saúde `Warning`/`Unhealthy`.
Se o ping for bloqueado mas a Internet responder por outros testes, o resultado é apenas **ALERTA**
(não PROBLEMA), evitando falsos positivos. O status de uma categoria é o pior de seus itens;
INDISPONÍVEL só prevalece se nenhum item pôde ser avaliado.

> As datas de fim de suporte (`LINUX_EOL`) são um dado fixo no código: revise-as periodicamente.

## Privacidade e segurança

- Nenhum dado do computador é enviado. As únicas comunicações de rede são **testes de diagnóstico**:
  ping/TCP para 8.8.8.8 e 1.1.1.1 e para o gateway local, resolução de nomes (google.com,
  microsoft.com, cloudflare.com), consulta DNS aos servidores configurados e conexão TCP à porta 443.
  Alvos podem ser trocados em `config.py` (ex.: servidores internos da empresa).
- O IP público **não** é consultado. Os relatórios ficam apenas no computador.
- Somente leitura: usa psutil, leitura do registro/arquivos do sistema e comandos nativos
  (`ping`, `route`, `powershell Get-*`, `apt list`, `lsblk`, `systemctl is-active`, `resolvectl`).
- Os relatórios contêm nome do PC, usuário, IPs e MACs: trate-os como informação interna.

## Limitações conhecidas

- **SMART/saúde de disco**: no Linux exige administrador (aparece como INDISPONÍVEL); no Windows
  depende do `Get-PhysicalDisk`.
- **Firewall no Linux**: `ufw status` exige root; o DiagTool usa o arquivo `/etc/ufw/ufw.conf` e o
  `systemctl`. Se não for possível determinar, o item é INDISPONÍVEL (nunca "chutado").
- **Atualizações no Linux**: usa o cache local do `apt` (sem `apt update`, que exige root); se o
  cache estiver velho, o relatório avisa. Outras famílias (dnf/pacman) não são cobertas.
- **Windows**: antivírus/atualizações dependem do PowerShell e da Central de Segurança
  (indisponíveis em edições Server, por exemplo). Número de série vem do WMI/`Get-CimInstance`.
- Executáveis não assinados podem ser sinalizados pelo SmartScreen/antivírus (comum em
  PyInstaller `--onefile`). Em ambiente corporativo, assine o `.exe` ou peça a liberação (allowlist).
- O primeiro start do `--onefile` extrai arquivos temporários e pode levar alguns segundos.

## Solução de problemas

- *Nada apareceu na Área de Trabalho:* verifique também a pasta pessoal e a pasta temporária
  (o programa usa alternativas se a Área de Trabalho não for gravável) e procure `DiagTool_erro_*.log`.
- *Linux: o duplo clique não executa:* use `criar_atalho_linux.sh` ou execute `./DiagTool` no terminal.
- *Erro de glibc ao abrir no Linux:* recompile em um sistema mais antigo.

## Licença

Uso livre pela sua equipe; adapte conforme a necessidade.
