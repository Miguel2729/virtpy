📚 VirtPy - Manual Completo

🚀 Visão Geral

VirtPy é uma biblioteca Python para criação de ambientes virtuais verdadeiramente isolados usando Firejail. Oferece isolamento de filesystem, rede, processos e bibliotecas.

📊 Comparação com outras soluções

Característica VirtPy Python Venv Docker
Isolamento 🔥 Alto (Firejail) ❌ Nenhum ✅ Alto
Performance ⚡ Quase nativa ⚡ Excelente 🐢 Overhead
Inicialização ⏱️ 0.5-2s ⏱️ <0.1s ⏱️ 1-3s
Rede 🌐 Namespace próprio ❌ Nenhuma ✅ Completa
Segurança 🛡️ Isolamento real ❌ Nenhuma ✅ Boa

---

📦 Instalação

Pré-requisitos

```bash
# Linux obrigatório (Firejail depende do kernel Linux)
# Instale Firejail:
sudo apt install firejail  # Debian/Ubuntu
sudo yum install firejail  # RHEL/CentOS
sudo pacman -S firejail    # Arch
```

Instalação do VirtPy

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/virtpy.git
cd virtpy

# Ou use diretamente o arquivo
wget https://raw.githubusercontent.com/seu-usuario/virtpy/main/virtpy.py
```

---

🎯 Começando Rápido

Exemplo Básico

```python
from virtpy import VirtualEnviron

# Cria ambiente isolado
with VirtualEnviron("meu_ambiente") as env:
    # Executa comando dentro do ambiente
    result = env.process.run(["python", "-c", "print('Hello VirtPy!')"])
    print(result.stdout.decode())
```

Exemplo com Rede

```python
# Ambiente com IP próprio
env = VirtualEnviron(
    nome="web_app",
    ip="10.100.0.2",  # IP na rede isolada
    setup=[
        "python -m pip install flask",
        "mkdir -p /app"
    ]
)

env.start()
env.process.run(["python", "/app/web_server.py"])
```

---

📖 API Principal

VirtualEnviron - Classe Principal

```python
env = VirtualEnviron(
    nome: str,                    # Nome do ambiente
    vars: Dict[str, str] = None,  # Variáveis de ambiente
    ip: str = None,               # IP para namespace de rede
    start: List[str] = None,      # Comandos ao iniciar
    setup: List[str] = None       # Comandos de setup
)
```

Métodos Principais

```python
# Gerenciamento do ambiente
env.start()                       # Inicia ambiente
env.shutdown()                    # Para ambiente
env.restart()                     # Reinicia
env.reinstall()                   # Limpa e reinstala

# Context manager
with VirtualEnviron("temp") as env:
    env.process.run(["ls", "/"])

# Network
env.test_network_connectivity()   # Testa conexão
env.run_in_namespace(["ping", "8.8.8.8"])  # Executa no namespace
```

---

📂 Sistema de Arquivos Virtual (env.fs)

Operações Básicas

```python
# Criar/remover diretórios
env.fs.mkdir("/data", parents=True)
env.fs.rmdir("/data")

# Arquivos
env.fs.write("/config.json", '{"debug": true}')
content = env.fs.read("/config.json")

# Listar arquivos
files = env.fs.listdir("/")
for root, dirs, files in env.fs.walk("/"):
    print(f"{root}: {len(files)} arquivos")

# Copiar dentro do ambiente
env.fs.copy("/source/file.txt", "/dest/file.txt")

# Importar/Exportar do HOST
env.fs.import_from_host("/home/user/script.py", "/app/main.py")
env.fs.export_to_host("/output/data.json", "/tmp/resultado.json")
```

Path Seguro

```python
# Todas as operações usam paths virtuais
# /app → /tmp/virtpy_env/app (automaticamente)
# Previne directory traversal attacks
```

---

🌍 Variáveis de Ambiente (env.environ)

Gerenciamento

```python
# Get/Set
env.environ.set("DEBUG", "1")
value = env.environ.get("PATH")

# Atualizar múltiplas
env.environ.update({
    "PYTHONPATH": "/app/lib",
    "LOG_LEVEL": "INFO"
})

# Listar todas
for key, value in env.environ.items():
    print(f"{key}={value}")

# Limpar/Substituir
env.environ.clear()          # Volta ao padrão
env.environ.replace(new_vars) # Substitui tudo
```

Variáveis Padrão

```bash
PATH=/tmp/virtpy_env/bin
USER=nome_do_ambiente
HOME=/tmp/virtpy_env
VIRTPY_ENV=nome_do_ambiente
LD_LIBRARY_PATH=/tmp/virtpy_env/lib
PYTHONPATH=/tmp/virtpy_env/lib/python
```

---

⚙️ Processos (env.process)

Executar Comandos

```python
# Comando simples
proc = env.process.run(["ls", "-la"])

# Com captura de output
result = env.process.run(
    ["python", "script.py"],
    capture_output=True,
    input_data=b"entrada"
)
print(result.stdout.decode())

# Com working directory
env.process.run(["git", "init"], cwd="/projeto")

# Com variáveis específicas
env.process.run(["echo", "$VAR"], env={"VAR": "valor"})
```

Gerenciamento de Processos

```python
# Listar processos
procs = env.process.list()
for p in procs:
    print(f"PID {p['pid']}: {p['command']}")

# Matar processos
env.process.kill(pid, signal.SIGTERM)
env.process.terminate(pid)  # Graceful
env.process.killall()       # Todos processos

# Esperar processo
returncode = env.process.wait(pid, timeout=30)

# Comunicar com processo em execução
stdout, stderr = env.process.communicate(pid, b"input")
```

---

📦 Gerenciador de Pacotes (env.package)

Instalação/Remoção

```python
# Instalar do PyPI
env.package.install("requests")

# Instalar de URL/local
env.package.install("git+https://github.com/user/repo.git")
env.package.install("/local/package.tar.gz")

# Desinstalar
env.package.uninstall("numpy")

# Listar instalados
packages = env.package.list_installed()
# ['requests', 'numpy', 'pandas']
```

Módulos Python

```python
# Importar módulo do ambiente virtual
module = env.package.import_module("meu_modulo", from_env="virtual")

# Importar do sistema real (com sandbox)
sys_module = env.package.import_module("os", from_env="real-os")

# Criar módulo no ambiente
env.package.create_module("utils", """
def hello():
    return "Hello from virtual env!"
""")

# Copiar módulo do host
env.package.copy("json")  # Copia módulo json do host
```

---

🔗 Bibliotecas C (env.library)

Gerenciamento de Bibliotecas

```python
# Configurar path
env.library.set_path("/lib64")

# Copiar bibliotecas do sistema
env.library.copy("c")      # libc.so
env.library.copy("pthread") # libpthread.so
env.library.copy("ssl")    # libssl.so

# Criar biblioteca personalizada
success = env.library.create_lib("mylib", """
#include <stdio.h>
void hello() { printf("Hello from C!\\n"); }
""")
```

---

🔌 API Interna (env.internal_api)

Comunicação entre Processos

```python
# Dentro do ambiente virtual, importe:
import virtpy_api.internal as vapi

# Obter informações do ambiente
info = vapi.get_env_info()

# Listar processos
procs = vapi.list_procs()

# Memória compartilhada
vapi.create_shared("buffer", 4096)
vapi.write_to_shared("buffer", dados)
data = vapi.read_from_shared("buffer")

# Serviços e IPC
vapi.register_service("web_api", 8080)
services = vapi.discover_services()
vapi.send_to_service("web_api", {"action": "ping"})

# Logs
vapi.log("INFO", "Processo iniciado", extra={"pid": 123})
logs = vapi.get_logs(limit=50)
```

---

🌐 Rede e Namespaces

Configuração de Rede

```python
# Ambiente com rede isolada
env = VirtualEnviron(
    nome="net_app",
    ip="10.100.0.2",           # IP no namespace
    setup=[
        "apt install curl",   # Pode instalar pacotes de rede
        "mkdir -p /var/www"
    ]
)

# Testar conectividade
if env.test_network_connectivity("8.8.8.8"):
    print("Conectividade OK")

# Executar no namespace
result = env.run_in_namespace(
    ["curl", "-s", "https://api.github.com"],
    capture_output=True
)
```

DNS e Resolução

```python
# DNS configurado automaticamente:
# - 8.8.8.8 (Google)
# - 8.8.4.4 (Google)
# - 1.1.1.1 (Cloudflare)

# Arquivo /etc/hosts personalizado:
env.fs.write("/etc/hosts", """
127.0.0.1   localhost
10.100.0.2  meu_ambiente
""")
```

---

🛡️ Segurança

Isolamento Garantido

```python
# Firejail fornece:
# - Chroot filesystem
# - Network namespace
# - PID namespace
# - IPC namespace
# - UTS namespace (hostname)
# - Seccomp filters
# - Capabilities dropped

# Prevenção de ataques:
# - Directory traversal (bloqueado)
# - Shell injection (comandos filtrados)
# - Symlink attacks (detectados)
```

Configurações de Segurança

```python
# Processos executam com:
# --noroot (sem privilégios)
# --caps.drop=all (sem capabilities)
# --seccomp (filtro syscalls)
# --private-dev (dispositivos mínimos)

# Filesystem:
# LD_LIBRARY_PATH restrito ao ambiente
# PATH validado para evitar escapes
```

---

🔄 Casos de Uso Comuns

1. Sandbox para Código Não-Confíavel

```python
def test_untrusted_code(code_path):
    with VirtualEnviron("sandbox", ip="10.100.0.99") as env:
        # Importar código para análise
        env.fs.import_from_host(code_path, "/analysis/script.py")
        
        # Executar em ambiente seguro
        result = env.process.run(
            ["python", "/analysis/script.py"],
            capture_output=True
        )
        
        # Analisar resultado
        return analyze_result(result)
```

2. Ambiente de Desenvolvimento Isolado

```python
class DevEnvironment:
    def __init__(self, project_path):
        self.env = VirtualEnviron(
            nome=f"dev_{project_name}",
            vars={"DEBUG": "1", "PYTHONPATH": "/app"},
            setup=[
                f"cp -r {project_path} /app",
                "python -m pip install -r /app/requirements.txt"
            ]
        )
    
    def test(self):
        return self.env.process.run(
            ["python", "-m", "pytest", "/app/tests"],
            capture_output=True
        )
```

3. CI/CD Pipeline Seguro

```python
def ci_pipeline(repo_url):
    env = VirtualEnviron("ci_runner", ip="10.100.0.100")
    
    # Clone e build isolado
    env.process.run(["git", "clone", repo_url, "/src"])
    env.process.run(["python", "-m", "pip", "install", "/src"])
    
    # Executar testes
    test_result = env.process.run(
        ["python", "-m", "pytest", "/src/tests"],
        capture_output=True
    )
    
    # Coletar resultados
    env.fs.export_to_host("/src/test_report.json", "reports/")
    
    env.shutdown()
    return test_result.returncode == 0
```

4. Análise Forense/Malware Python

```python
def analyze_python_malware(malware_path):
    env = VirtualEnviron(
        nome="malware_lab",
        ip="10.100.0.66",
        vars={"PYTHONDONTWRITEBYTECODE": "1"}
    )
    
    # Isolar malware
    env.fs.import_from_host(malware_path, "/malware/sample.py")
    
    # Monitorar atividade
    env.process.run(["python", "/malware/sample.py"])
    
    # Capturar logs e network
    logs = env.internal_api.get_logs()
    network_data = env.run_in_namespace(
        ["tcpdump", "-n", "-c", "100"],
        capture_output=True
    )
    
    return {"logs": logs, "network": network_data}
```

---

⚠️ Limitações e Considerações

Compatibilidade

· ✅ Linux apenas (requer Firejail e namespaces)
· ❌ Windows/Mac não suportados
· ✅ Python 3.6+

Requisitos de Sistema

```bash
# Permissões necessárias
sudo apt install firejail           # Requer sudo para instalação
python virtpy_app.py               # Não requer root para execução

# Espaço em disco
# Cada ambiente: 5-50MB (dependendo dos pacotes)

# Memória
# Overhead mínimo (~10MB por ambiente)
```

Considerações de Segurança

```python
# 1. Firejail requer atenção
#    - Mantenha atualizado
#    - Use versões estáveis

# 2. Namespace de rede
#    - NAT pode vazar em configurações erradas
#    - Use IPs em subnets privadas

# 3. Resource limits
#    - VirtPy NÃO limita CPU/memória
#    - Use cgroups separados se necessário
```

---

🔧 Solução de Problemas

Problemas Comuns

```python
# 1. Firejail não instalado
#    Erro: "firejail: command not found"
#    Solução: sudo apt install firejail

# 2. Permissão negada
#    Erro: "PermissionError: [Errno 13]"
#    Solução: Verificar se Firejail foi instalado com sudo

# 3. Rede não funciona
#    Verifique: env.test_network_connectivity()
#    Solução: Execute com sudo ou ajuste permissões de rede

# 4. Espaço insuficiente
#    Limpe ambientes antigos: rm -rf /tmp/virtpy_*

# 5. Processos zumbis
#    Sempre use: env.shutdown() ou with statement
```

Debug

```python
# Habilitar logs detalhados
import logging
logging.basicConfig(level=logging.DEBUG)

# Verificar estado do ambiente
print(f"Base path: {env._base_path}")
print(f"Running: {env._running}")
print(f"Processes: {len(env.process._processes)}")

# Testar componentes
env.fs.write("/test.txt", "test")
assert env.fs.read("/test.txt") == "test"
```

---

📈 Performance

Benchmarks (exemplo)

```python
# Tempos médios (i7-10700K, SSD NVMe)
# Criação ambiente: 0.8s
# Execução comando: 0.1s
# Importar 100MB: 1.2s
# Network ping: 0.05s

# Comparação overhead:
# VirtPy: 1-5% overhead
# Docker: 5-15% overhead
# VM: 20-50% overhead
```

Otimizações

```python
# 1. Reutilizar ambientes
env = VirtualEnviron("cache")
# ... múltiplas operações
# Não destrua entre operações

# 2. Cache de pacotes
env.fs.import_from_host("/var/cache/pip", "/var/cache/pip")

# 3. Evitar shutdown/start frequentes
# Use context manager apenas quando necessário
```

---

🤝 Contribuindo

Roadmap

· Suporte a Windows (via WSL2)
· Integração com Docker
· GUI/Web interface
· Plugin system
· Cluster/Orchestration

Reportando Issues

```bash
# Inclua informações:
python -c "import platform; print(platform.platform())"
firejail --version
python --version

# Reproduza o problema:
# 1. Código mínimo que reproduz
# 2. Output completo
# 3. Logs do Firejail (--debug)
```

---

📄 Licença e Agradecimentos

Licença

```
MIT License - Use livre para qualquer propósito
```

Dependências

· Firejail: Sandboxing (GPLv2)
· Python 3.6+: Runtime
· Linux: Kernel namespaces

Agradecimentos

```python
# VirtPy foi inspirado por:
# - Docker (containerization)
# - Python venv (simplicidade)
# - Firejail (segurança prática)
# - E todos os contribuidores!
```

---

🎉 Exemplo Final Completo

```python
from virtpy import VirtualEnviron
import json

def full_example():
    # Cria ambiente com tudo
    env = VirtualEnviron(
        nome="full_demo",
        ip="10.100.0.10",
        vars={"ENV": "production", "LOG_LEVEL": "DEBUG"},
        setup=[
            "python -m pip install requests pandas",
            "mkdir -p /data /logs"
        ]
    )
    
    # Importar código
    env.fs.import_from_host("app.py", "/app/main.py")
    
    # Configurar
    env.fs.write("/config.json", json.dumps({"timeout": 30}))
    env.environ.set("CONFIG_PATH", "/config.json")
    
    # Executar
    result = env.process.run(
        ["python", "/app/main.py", "--input", "/data/source.csv"],
        capture_output=True,
        cwd="/app"
    )
    
    # Coletar resultados
    if result.returncode == 0:
        env.fs.export_to_host("/logs/output.log", "result.log")
        print("Sucesso!")
    else:
        print(f"Falhou: {result.stderr.decode()}")
    
    # Limpar
    env.shutdown()

if __name__ == "__main__":
    full_example()
```

---

✨ VirtPy: Ambientes Python verdadeiramente isolados, sem complexidade.
