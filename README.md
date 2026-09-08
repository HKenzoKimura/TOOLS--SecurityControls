# 🛡️ Check-SecurityControls.ps1 — Endpoint Security Baseline Auditor

> **Context:** Script PowerShell **somente-leitura** de auditoria de postura de segurança em endpoints Windows. Coleta o estado real de BitLocker, EDR, Firewall, UAC, SMBv1, RDP, hardening do PowerShell, LSA/Credential Guard, Windows Update, contas privilegiadas e serviços críticos — pensado como baseline pré-engajamento de pentest interno ou como rotina periódica de compliance.
>
> ⚠️ *Não altera nenhuma configuração do sistema. Requer execução como Administrador para resultados completos (vários checks dependem de WMI/registro elevado).*

---

## `$ cat ./objective.txt`

Fornecer um snapshot único e reprodutível da postura de segurança de um endpoint, cobrindo o ciclo:

1. **Descoberta** — enumerar o estado atual de cada controle (habilitado/desabilitado, versão, configuração)
2. **Classificação** — atribuir status `OK` / `WARN` / `FAIL` / `INFO` a cada item coletado
3. **Consolidação** — agregar tudo em uma estrutura única, ordenada por categoria
4. **Exportação** — opcionalmente serializar o relatório em JSON para análise ou correlação posterior

---

## `$ cat ./why_baseline_matters.txt`

### Por que auditar antes de um pentest (ou periodicamente)

Um pentest interno mede a *exploração*; este script mede a *exposição de base* — o que já está mal configurado independentemente de qualquer ataque ativo. Controles como BitLocker desligado, SMBv1 habilitado ou contas extras no grupo Administradores não são "vulnerabilidades" no sentido de CVE, mas são exatamente o tipo de configuração que amplia o blast radius de qualquer comprometimento inicial.

```
Estado inseguro (ex: SMBv1 on, RDP sem NLA, Guest habilitado)
        │
        ▼
Pentest/ataque real explora ponto de entrada qualquer
        │
        ▼
Ausência de controles de contenção = movimento lateral trivial
```

Rodar esse script **antes** do engajamento dá ao time uma linha de base clara: "isto já estava fraco" vs. "isto foi explorado".

---

## `$ cat ./architecture.txt`

```
┌─────────────────────────────────────────────────────────────────────────┐
│              CHECK-SECURITYCONTROLS.PS1 — FLOW                          │
│                                                                         │
│  [Elevação?] ──► WMI/CIM + Registro + Cmdlets nativos                   │
│                          │                                              │
│         ┌────────────────┼────────────────────────────┐                │
│         ▼                ▼                             ▼                │
│    BitLocker         EDR/AV                        Firewall             │
│    (Get-BitLockerVolume  (CSFalconService,          (Get-NetFirewall-   │
│     ou manage-bde)        Get-MpComputerStatus,       Profile)          │
│                            SecurityCenter2)                             │
│         │                │                             │                │
│         ▼                ▼                             ▼                │
│    UAC / SMBv1 / RDP / PowerShell logging / LSA / Credential Guard      │
│         │                                                               │
│         ▼                                                               │
│    Windows Update / Contas locais / Serviços críticos / TPM             │
│         │                                                               │
│         ▼                                                               │
│    Add-Result → $results[categoria][chave] = { Value, Status }          │
│         │                                                               │
│         ├──► Console colorido (OK=verde, WARN=amarelo, FAIL=vermelho)   │
│         └──► [-ExportPath] → JSON (ConvertTo-Json -Depth 6)             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## `$ cat ./design_decisions.md`

### 1. `Add-Result` — Estrutura de dados única para console e export

```powershell
function Add-Result($category, $key, $value, $status = 'INFO') {
    if (-not $results.Contains($category)) { $results[$category] = [ordered]@{} }
    $results[$category][$key] = @{ Value = $value; Status = $status }
    ...
}
```

**Por que centralizar em uma função?**

Toda a lógica de exibição colorida e de acumulação no hashtable `[ordered]` passa por um único ponto. Isso garante que o que aparece no console é exatamente o que vai para o JSON exportado — não existem dois caminhos de dados divergentes. Usar `[ordered]` preserva a ordem de inserção das categorias e chaves, o que torna o JSON final legível e diffável entre execuções.

### 2. BitLocker — módulo PowerShell com fallback para `manage-bde`

```powershell
try {
    $bl = Get-BitLockerVolume -ErrorAction Stop
    ...
} catch {
    Add-Result 'BitLocker' 'Módulo PowerShell BitLocker' 'Indisponível...' 'WARN'
}
if (-not $blModuleOk) {
    $mbde = manage-bde -status 2>$null
    ...
}
```

**Por que dois caminhos?**

`Get-BitLockerVolume` não está presente em todas as edições/instalações do Windows. `manage-bde` é um binário nativo presente desde o Windows Vista, independente do módulo PowerShell estar instalado. O fallback garante cobertura em Server Core, edições enxutas ou ambientes com módulos removidos — sem isso, o check simplesmente falharia silenciosamente em parte da frota.

### 3. Verificação de Key Protectors — por que checar `RecoveryPassword` especificamente

```powershell
if ('RecoveryPassword' -notin $vol.KeyProtector.KeyProtectorType) {
    Add-Result 'BitLocker' "  Recovery Key presente [$($vol.MountPoint)]" 'NÃO ENCONTRADA' 'WARN'
}
```

Um volume pode estar "Protection=On" mas sem uma chave de recuperação (`RecoveryPassword`) escapada em AD/Entra ID/local. Nesse cenário, qualquer falha de TPM trava o volume permanentemente sem via de recuperação — um risco operacional tão real quanto um risco de segurança, e por isso é reportado separadamente do status geral de proteção.

### 4. EDR — múltiplas fontes de verdade, não apenas um serviço

```powershell
$csSvc = Get-Service -Name CSFalconService ...
$mp = Get-MpComputerStatus ...
$avList = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct ...
```

**Por que três checks para "tem EDR/AV"?**

Um serviço rodando (`CSFalconService`) não garante que o agente está funcional; `Get-MpComputerStatus` cobre a hipótese de Defender ser o AV ativo (mesmo em máquinas com Falcon, o Defender frequentemente continua presente em modo passivo); e o Security Center (`root\SecurityCenter2`) é a fonte que o próprio Windows usa para reportar "qual AV está registrado", útil para detectar produtos terceiros não previstos no script. Nenhuma fonte isolada é confiável o suficiente para reportar sozinha.

### 5. `$ErrorActionPreference = 'SilentlyContinue'` — trade-off consciente

```powershell
$ErrorActionPreference = 'SilentlyContinue'
```

**Por que suprimir erros globalmente?**

O script roda em uma frota heterogênea (VMs sem TPM, Server Core sem GUI, edições Home sem BitLocker completo). Sem essa supressão, qualquer cmdlet ausente interromperia toda a auditoria no primeiro erro. O trade-off é que erros reais de permissão/timeout ficam menos visíveis — por isso cada check crítico tem seu próprio `try/catch` reportando `WARN`, em vez de depender apenas da supressão global.

### 6. Nomes de grupo local em pt-BR com fallback en-US

```powershell
$admins = Get-LocalGroupMember -Group 'Administradores' -ErrorAction SilentlyContinue
if (-not $admins) { $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
```

Grupos locais built-in do Windows têm nome de exibição diferente conforme o idioma de instalação, mas o SID é o mesmo (`S-1-5-32-544`). O script usa o nome amigável (mais legível no relatório) com fallback, em vez de resolver por SID, priorizando legibilidade do output sobre robustez absoluta — uma limitação conhecida caso o ambiente use outro idioma além de pt-BR/en-US.

---

## `$ cat ./nist_csf_mapping.yml`

```yaml
# Mapeamento dos controles auditados para NIST Cybersecurity Framework (funções)
# e CIS Controls v8, para uso em relatórios de compliance / gap analysis

identify:
  - CIS-1   # Inventário de ativos → seção "Informações do Sistema"

protect:
  - CIS-3   # Proteção de dados → BitLocker (criptografia em repouso)
  - CIS-4   # Configuração segura → UAC, SMBv1, RDP/NLA, Execution Policy
  - CIS-5   # Gestão de contas → Contas locais / grupo Administradores / Guest
  - CIS-6   # Controle de acesso → LSA Protection, Credential Guard
  - CIS-9   # Proteção de e-mail/browser → (fora de escopo deste script)
  - CIS-12  # Gestão de infraestrutura de rede → Firewall profiles

detect:
  - CIS-8   # Gestão de logs de auditoria → ScriptBlockLogging, ModuleLogging,
            #   Transcription (PowerShell logging)
  - CIS-10  # Defesas contra malware → EDR (CrowdStrike/Defender), SecurityCenter2

respond:
  - CIS-17  # (fora de escopo — script é apenas de coleta, não de resposta)

recover:
  - CIS-11  # Recuperação de dados → BitLocker Recovery Key presente/ausente
```

> Diferente de um mapeamento MITRE ATT&CK (usado para ferramentas ofensivas), aqui o mapeamento relevante é **defensivo**: cada categoria do script corresponde a um controle de baseline dos frameworks NIST CSF / CIS Controls, e não a uma tática de ataque.

---

## `$ cat ./prerequisites.sh`

```powershell
# Nenhuma dependência externa — usa apenas cmdlets/módulos nativos do Windows.
# Módulos opcionais, usados quando presentes (com fallback ou WARN quando ausentes):
#   - BitLocker           (Get-BitLockerVolume)
#   - Defender             (Get-MpComputerStatus)
#   - TrustedPlatformModule (Get-Tpm)

# Verificar elevação antes de rodar:
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# Se necessário, ajustar Execution Policy apenas para a sessão atual:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

> **Por que rodar elevado é importante?**
> Vários checks (BitLocker key protectors, chaves em `HKLM:\SYSTEM\...`, TPM, Credential Guard) exigem contexto de Administrador para retornar dados completos. Sem elevação, o script ainda executa — mas o relatório final pode subestimar o risco real por falta de visibilidade, não por ausência do controle.

---

## `$ cat ./usage.sh`

```powershell
# Execução simples — saída apenas no console
.\Check-SecurityControls.ps1

# Execução com exportação do relatório completo em JSON
.\Check-SecurityControls.ps1 -ExportPath C:\Temp\report.json
```

```
# Output esperado (trecho):
Executando como Administrador: True

=== BitLocker ===
  Volume C:                              : Protection=On | Encryption=100% | Method=XtsAes256

=== EDR / Antivírus ===
  CrowdStrike Falcon Service              : Running
  Defender RealTimeProtection             : True

=== Firewall ===
  Domain Profile Enabled                  : True

...

Itens em FAIL : 0
Itens em WARN : 3

Relatório exportado para: C:\Temp\report.json
```

```powershell
# Consolidar múltiplos relatórios (ex: uma execução por host) para análise em lote
Get-ChildItem C:\Reports\*.json | ForEach-Object {
    $r = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{ Host = $_.BaseName; BitLockerC = $r.BitLocker.'Volume C:'.Status }
} | Format-Table
```

---

## `$ cat ./blind_spots.md`

> Assim como um README ofensivo documenta "opportunities de detecção", aqui documentamos o inverso: pontos onde este script de auditoria **pode não capturar o estado real** — importante para não confiar cegamente em um `OK` isolado.

| Limitação | Por que acontece | Mitigação |
|---|---|---|
| Falso `OK` em EDR | Serviço `CSFalconService` "Running" não garante que o sensor está reportando ao console de gestão (pode estar isolado/desregistrado) | Correlacionar com o console CrowdStrike (last seen), não apenas com o status local do serviço |
| BitLocker "Protection=On" sem chave de recuperação escapada | O script reporta isso como `WARN` separado, mas é fácil ignorar em uma leitura rápida do console | Sempre revisar a seção `KeyProtector` completa, não só o status agregado |
| Execução sem elevação | Vários checks retornam `$null`/vazio silenciosamente (`SilentlyContinue`) em vez de erro visível | Sempre confirmar `Executando como Administrador: True` no topo da saída antes de confiar no relatório |
| Ambientes localizados fora de pt-BR/en-US | Nomes de grupo local (`Administradores`/`Administrators`) não têm fallback para outros idiomas | Adaptar o script para resolver pelo SID `S-1-5-32-544` em vez do nome, se a frota for multilíngue |
| Snapshot pontual | O script mede o estado no momento da execução, não deriva/drift ao longo do tempo | Agendar execuções periódicas (Task Scheduler / GPO) e comparar os JSONs exportados historicamente |

---

## `$ cat ./lessons_learned.txt`

```
[+] Centralizar Value+Status em uma única estrutura evita divergência entre console e export
[+] Fallback manage-bde garante cobertura mesmo sem o módulo PowerShell BitLocker
[+] Checar múltiplas fontes de EDR/AV (serviço + cmdlet + SecurityCenter2) reduz falso-negativo
[+] JSON estruturado por categoria facilita consolidação em escala (múltiplos hosts)
[-] $ErrorActionPreference global mascara detalhes de erro úteis para diagnóstico fino
[-] Resolução de grupo local por nome (não SID) quebra em idiomas além de pt-BR/en-US
[-] Sem parametrização de quais categorias rodar — hoje é tudo ou nada
[-] Sem timestamp embutido no relatório — depende do nome do arquivo/ExportPath para versionar no tempo
[→] Melhorias: adicionar -Categories para seleção seletiva, timestamp no JSON, resolução por SID,
    e um modo -Baseline que compara contra uma execução anterior e destaca apenas o que mudou
```

---

<p align="center">
  <i>Read-only security baseline · Não altera configurações · CIS Controls v8 / NIST CSF mapping</i>
</p>
