"""
Core implementation of VirtPy - Complete Virtual Environments, v2.8.5
"""
"""
## Why No Windows Support (And Never Will Be)

### Technical Reality:
1. **Windows lacks process namespaces** → No real process isolation
2. **No proper chroot equivalent** → Filesystem isolation is theater  
3. **Security model is binary** → Either full access or no access
4. **No lightweight copy-on-write** → Containers become VM-heavy
5. There is no Firejail for Windows.

### What Others Do:
- Docker Desktop: Runs a Linux VM (hidden)
- WSL2: Is literally Linux in a VM
- Python venv: Just PATH manipulation (no isolation)

### Our Choice:
We refuse to pretend. Either real isolation (Linux) or nothing.
"""

import os
import sys
import json
import shutil
import signal
import socket
import subprocess
import threading
import tempfile
import select
import time
import builtins
import importlib
import importlib.util
import inspect
import ctypes
import fcntl
import errno
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
import uuid
import atexit
import textwrap
import glob
import re

if os.name != "posix":
    print("[warning] Operating system other than Linux. May not function as expected.")


print("Checking firejail...")

# Check installation
if subprocess.run(["which", "firejail"]).returncode == 0:
    print("WARNING: Already installed")
    subprocess.run(["firejail", "--version"])
    exit()

# Try to install
pms = ["apt", "apt-get", "dnf", "yum"]

for pm in pms:
    if subprocess.run(["which", pm]).returncode == 0:
        print(f"WARNING: Installing with {pm}...")
        
        if pm in ["apt", "apt-get"]:
            cmd = f"sudo {pm} update && sudo {pm} install -y firejail"
        else:
            cmd = f"sudo {pm} install -y firejail"
        
        result = subprocess.run(cmd, shell=True)
        
        if result.returncode == 0:
            print("SUCCESS: Installed!")
            break
        else:
            print("ERROR: Failed")

# Check result
if subprocess.run(["which", "firejail"]).returncode != 0:
    print("WARNING: Security vulnerability - no sandbox installed")

class SecurityError(Exception):
	pass

class VirtPyInternalAPI:
    """API interna disponível para processos dentro do ambiente"""
    
    def __init__(self, environ_instance: 'VirtualEnviron'):
        self._env = environ_instance
        self._setup_internal_paths()
    
    def _setup_internal_paths(self):
        """Configura paths para a API interna"""
        # Cria diretório para módulos da API
        api_dir = os.path.join(self._env._base_path, 'lib', 'virtpy_api')
        os.makedirs(api_dir, exist_ok=True)
        
        # Adiciona ao PYTHONPATH do ambiente
        current_pythonpath = self._env.environ.get('PYTHONPATH', '')
        if api_dir not in current_pythonpath:
            self._env.environ.set('PYTHONPATH', f"{api_dir}:{current_pythonpath}")
    
    def expose_to_environment(self):
        """Expõe a API para o ambiente"""
        # Cria módulo Python que processos podem importar
        api_module = """
# VirtPy Internal API Module
# Available to processes inside the virtual environment

import os
import sys
import json
import subprocess
import threading
from typing import Dict, List, Optional, Any

class ProcessAPI:
    \"\"\"API para processos dentro do ambiente\"\"\"
    
    def __init__(self):
        self._api_socket = os.environ.get('VIRTPY_API_SOCKET')
        self._env_name = os.environ.get('VIRTPY_ENV')
        
    def _call_api(self, endpoint: str, data: Dict = None) -> Dict:
        \"\"\"Chama a API interna\"\"\"
        if not self._api_socket:
            return {'success': False, 'error': 'API not available'}
        
        try:
            import socket
            import json
            
            # Conecta ao socket da API
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self._api_socket)
            
            # Envia requisição
            request = {
                'endpoint': endpoint,
                'data': data or {},
                'pid': os.getpid(),
                'cwd': os.getcwd()
            }
            
            client.send(json.dumps(request).encode() + b'\\n')
            
            # Recebe resposta
            response_data = b''
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b'\\n' in chunk:
                    break
            
            client.close()
            
            # Parse resposta
            response = json.loads(response_data.decode().strip())
            return response
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ========== MÉTODOS DA API ==========
    
    def get_environment_info(self) -> Dict:
        \"\"\"Obtém informações do ambiente\"\"\"
        return self._call_api('environment/info')
    
    def list_processes(self) -> Dict:
        \"\"\"Lista processos no ambiente\"\"\"
        return self._call_api('process/list')
    
    def get_process_info(self, pid: Optional[int] = None) -> Dict:
        \"\"\"Obtém informações de um processo\"\"\"
        if pid is None:
            pid = os.getpid()
        return self._call_api('process/info', {'pid': pid})
    
    def communicate_with_process(self, pid: int, message: str) -> Dict:
        \"\"\"Envia mensagem para outro processo\"\"\"
        return self._call_api('process/communicate', {
            'target_pid': pid,
            'message': message
        })
    
    def create_shared_memory(self, name: str, size: int = 1024) -> Dict:
        \"\"\"Cria área de memória compartilhada\"\"\"
        return self._call_api('memory/create', {
            'name': name,
            'size': size
        })
    
    def read_shared_memory(self, name: str) -> Dict:
        \"\"\"Lê da memória compartilhada\"\"\"
        return self._call_api('memory/read', {'name': name})
    
    def write_shared_memory(self, name: str, data: Any) -> Dict:
        \"\"\"Escreve na memória compartilhada\"\"\"
        return self._call_api('memory/write', {
            'name': name,
            'data': data
        })
    
    def create_named_pipe(self, name: str) -> Dict:
        \"\"\"Cria um pipe nomeado\"\"\"
        return self._call_api('pipe/create', {'name': name})
    
    def write_to_pipe(self, name: str, data: str) -> Dict:
        \"\"\"Escreve em um pipe\"\"\"
        return self._call_api('pipe/write', {
            'name': name,
            'data': data
        })
    
    def read_from_pipe(self, name: str, timeout: float = 5.0) -> Dict:
        \"\"\"Lê de um pipe\"\"\"
        return self._call_api('pipe/read', {
            'name': name,
            'timeout': timeout
        })
    
    def register_service(self, name: str, port: int = 0) -> Dict:
        \"\"\"Registra um serviço no ambiente\"\"\"
        return self._call_api('service/register', {
            'name': name,
            'port': port
        })
    
    def discover_services(self) -> Dict:
        \"\"\"Descobre serviços disponíveis\"\"\"
        return self._call_api('service/discover')
    
    def send_message(self, service_name: str, message: Dict) -> Dict:
        \"\"\"Envia mensagem para um serviço\"\"\"
        return self._call_api('service/send', {
            'service': service_name,
            'message': message
        })
    
    def create_event(self, name: str) -> Dict:
        \"\"\"Cria um evento\"\"\"
        return self._call_api('event/create', {'name': name})
    
    def wait_event(self, name: str, timeout: float = None) -> Dict:
        \"\"\"Espera por um evento\"\"\"
        return self._call_api('event/wait', {
            'name': name,
            'timeout': timeout
        })
    
    def signal_event(self, name: str) -> Dict:
        \"\"\"Sinaliza um evento\"\"\"
        return self._call_api('event/signal', {'name': name})
    
    def get_metrics(self) -> Dict:
        \"\"\"Obtém métricas do ambiente\"\"\"
        return self._call_api('system/metrics')
    
    def log_message(self, level: str, message: str, extra: Dict = None) -> Dict:
        \"\"\"Registra uma mensagem de log\"\"\"
        return self._call_api('log/write', {
            'level': level,
            'message': message,
            'extra': extra or {}
        })
    
    def get_logs(self, limit: int = 100) -> Dict:
        \"\"\"Obtém logs do ambiente\"\"\"
        return self._call_api('log/read', {'limit': limit})
    
    def create_lock(self, name: str) -> Dict:
        \"\"\"Cria um lock\"\"\"
        return self._call_api('lock/create', {'name': name})
    
    def acquire_lock(self, name: str, timeout: float = None) -> Dict:
        \"\"\"Adquire um lock\"\"\"
        return self._call_api('lock/acquire', {
            'name': name,
            'timeout': timeout
        })
    
    def release_lock(self, name: str) -> Dict:
        \"\"\"Libera um lock\"\"\"
        return self._call_api('lock/release', {'name': name})
    
    def broadcast(self, channel: str, message: Any) -> Dict:
        \"\"\"Transmite mensagem em um canal\"\"\"
        return self._call_api('broadcast/send', {
            'channel': channel,
            'message': message
        })
    
    def subscribe(self, channel: str) -> Dict:
        \"\"\"Inscreve-se em um canal\"\"\"
        return self._call_api('broadcast/subscribe', {'channel': channel})
    
    def check_health(self) -> Dict:
        \"\"\"Verifica saúde do processo\"\"\"
        return self._call_api('health/check')

# Instância global da API
api = ProcessAPI()

# Funções de conveniência
def get_env_info():
    \"\"\"Obtém informações do ambiente\"\"\"
    return api.get_environment_info()

def list_procs():
    \"\"\"Lista processos\"\"\"
    return api.list_processes()

def create_shared(name, size=1024):
    \"\"\"Cria memória compartilhada\"\"\"
    return api.create_shared_memory(name, size)

def send_to_process(pid, message):
    \"\"\"Envia mensagem para processo\"\"\"
    return api.communicate_with_process(pid, message)

def register_svc(name, port=0):
    \"\"\"Registra serviço\"\"\"
    return api.register_service(name, port)

def discover_svcs():
    \"\"\"Descobre serviços\"\"\"
    return api.discover_services()

def log(level, message, **extra):
    \"\"\"Registra log\"\"\"
    return api.log_message(level, message, extra)

def metrics():
    \"\"\"Obtém métricas\"\"\"
    return api.get_metrics()
"""
        
        # Salva o módulo no ambiente
        api_file = os.path.join(self._env._base_path, 'lib', 'virtpy_api', 'internal.py')
        with open(api_file, 'w') as f:
            f.write(api_module)
    
    def start_api_server(self):
        """Inicia servidor da API interna"""
        import socket
        import threading
        import json
        
        # Cria socket para API
        socket_path = os.path.join(self._env._base_path, 'virtpy_api.sock')
        
        # Remove socket antigo se existir
        try:
            os.unlink(socket_path)
        except:
            pass
        
        # Cria estrutura de dados para API
        self._shared_memory = {}
        self._named_pipes = {}
        self._events = {}
        self._locks = {}
        self._services = {}
        self._broadcast_channels = {}
        self._logs = []
        self._api_lock = threading.Lock()
        
        def handle_api_request(conn, addr):
            """Manipula requisições da API"""
            try:
                # Recebe dados
                data = b''
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b'\n' in chunk:
                        break
                
                if not data:
                    conn.close()
                    return
                
                # Parse requisição
                request = json.loads(data.decode().strip())
                endpoint = request.get('endpoint', '')
                request_data = request.get('data', {})
                pid = request.get('pid')
                cwd = request.get('cwd')
                
                # Processa endpoint
                response = self._process_api_request(endpoint, request_data, pid, cwd)
                
                # Envia resposta
                conn.send(json.dumps(response).encode() + b'\n')
                conn.close()
                
            except Exception as e:
                response = {'success': False, 'error': str(e)}
                try:
                    conn.send(json.dumps(response).encode() + b'\n')
                except:
                    pass
                conn.close()
        
        def api_server():
            """Servidor da API"""
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            server.listen(5)
            
            # Torna o socket acessível para processos no ambiente
            os.chmod(socket_path, 0o666)
            
            while True:
                try:
                    conn, addr = server.accept()
                    thread = threading.Thread(target=handle_api_request, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                except:
                    break
            
            server.close()
        
        # Inicia servidor em thread
        self._api_server_thread = threading.Thread(target=api_server)
        self._api_server_thread.daemon = True
        self._api_server_thread.start()
        
        # Configura variável de ambiente para processos
        self._env.environ.set('VIRTPY_API_SOCKET', socket_path)
        
        return socket_path
    
    def _process_api_request(self, endpoint: str, data: dict, pid: int, cwd: str) -> dict:
        """Processa requisições da API"""
        
        # Endpoints de sistema
        if endpoint == 'system/metrics':
            return self._get_system_metrics()
        
        elif endpoint == 'health/check':
            return {'success': True, 'status': 'healthy', 'pid': pid}
        
        # Endpoints de ambiente
        elif endpoint == 'environment/info':
            return {
                'success': True,
                'environment': self._env.name,
                'base_path': self._env._base_path,
                'variables': dict(self._env.environ.items()),
                'process_count': len(self._env.process._processes)
            }
        
        # Endpoints de processo
        elif endpoint == 'process/list':
            with self._api_lock:
                processes = []
                for proc_pid, proc in self._env.process._processes.items():
                    processes.append({
                        'pid': proc_pid,
                        'command': ' '.join(proc.args) if isinstance(proc.args, list) else str(proc.args),
                        'status': 'running' if proc.poll() is None else 'exited',
                        'returncode': proc.returncode
                    })
                return {'success': True, 'processes': processes}
        
        elif endpoint == 'process/info':
            target_pid = data.get('pid', pid)
            
            with self._api_lock:
                if target_pid in self._env.process._processes:
                    proc = self._env.process._processes[target_pid]
                    return {
                        'success': True,
                        'pid': target_pid,
                        'status': 'running' if proc.poll() is None else 'exited',
                        'returncode': proc.returncode,
                        'command': ' '.join(proc.args) if isinstance(proc.args, list) else str(proc.args)
                    }
                else:
                    return {'success': False, 'error': f'Process {target_pid} not found'}
        
        elif endpoint == 'process/communicate':
            target_pid = data.get('target_pid')
            message = data.get('message', '')
            
            # Em uma implementação real, aqui você enviaria a mensagem para o processo
            # Por enquanto, apenas registra
            self._log_message('INFO', f'Process {pid} sent message to {target_pid}: {message[:50]}...')
            
            return {
                'success': True,
                'message': f'Message sent to process {target_pid}',
                'from_pid': pid
            }
        
        # Endpoints de memória compartilhada
        elif endpoint == 'memory/create':
            name = data.get('name')
            size = data.get('size', 1024)
            
            with self._api_lock:
                if name in self._shared_memory:
                    return {'success': False, 'error': f'Shared memory {name} already exists'}
                
                self._shared_memory[name] = {
                    'data': b'',
                    'size': size,
                    'created_by': pid,
                    'created_at': time.time()
                }
                
                return {'success': True, 'name': name, 'size': size}
        
        elif endpoint == 'memory/read':
            name = data.get('name')
            
            with self._api_lock:
                if name not in self._shared_memory:
                    return {'success': False, 'error': f'Shared memory {name} not found'}
                
                shared = self._shared_memory[name]
                # Em uma implementação real, você retornaria os dados
                # Por simplicidade, retornamos informações
                return {
                    'success': True,
                    'name': name,
                    'size': len(shared['data']),
                    'created_by': shared['created_by'],
                    'has_data': len(shared['data']) > 0
                }
        
        elif endpoint == 'memory/write':
            name = data.get('name')
            write_data = data.get('data')
            
            with self._api_lock:
                if name not in self._shared_memory:
                    return {'success': False, 'error': f'Shared memory {name} not found'}
                
                # Convert data to bytes
                if isinstance(write_data, str):
                    write_data = write_data.encode()
                
                self._shared_memory[name]['data'] = write_data
                self._shared_memory[name]['last_modified'] = time.time()
                self._shared_memory[name]['last_modified_by'] = pid
                
                return {
                    'success': True,
                    'name': name,
                    'size': len(write_data),
                    'message': f'Data written to shared memory {name}'
                }
        
        # Endpoints de log
        elif endpoint == 'log/write':
            level = data.get('level', 'INFO')
            message = data.get('message', '')
            extra = data.get('extra', {})
            
            log_entry = {
                'timestamp': time.time(),
                'level': level,
                'message': message,
                'pid': pid,
                'cwd': cwd,
                'extra': extra
            }
            
            with self._api_lock:
                self._logs.append(log_entry)
                # Mantém apenas os últimos 1000 logs
                if len(self._logs) > 1000:
                    self._logs = self._logs[-1000:]
            
            return {'success': True, 'logged': True, 'message': 'Log recorded'}
        
        elif endpoint == 'log/read':
            limit = data.get('limit', 100)
            
            with self._api_lock:
                logs = self._logs[-limit:] if self._logs else []
                return {
                    'success': True,
                    'logs': logs,
                    'count': len(logs),
                    'total': len(self._logs)
                }
        
        # Endpoints de serviço
        elif endpoint == 'service/register':
            name = data.get('name')
            port = data.get('port', 0)
            
            with self._api_lock:
                if name in self._services:
                    return {'success': False, 'error': f'Service {name} already registered'}
                
                self._services[name] = {
                    'pid': pid,
                    'port': port,
                    'registered_at': time.time(),
                    'cwd': cwd
                }
            
            return {
                'success': True,
                'service': name,
                'port': port,
                'message': f'Service {name} registered by process {pid}'
            }
        
        elif endpoint == 'service/discover':
            with self._api_lock:
                services = []
                for name, info in self._services.items():
                    services.append({
                        'name': name,
                        'pid': info['pid'],
                        'port': info['port'],
                        'registered_at': info['registered_at']
                    })
                
                return {'success': True, 'services': services}
        
        elif endpoint == 'service/send':
            service_name = data.get('service')
            message = data.get('message', {})
            
            with self._api_lock:
                if service_name not in self._services:
                    return {'success': False, 'error': f'Service {service_name} not found'}
                
                service_info = self._services[service_name]
                
                # Em uma implementação real, você enviaria a mensagem para o processo do serviço
                # Por enquanto, apenas registra
                self._log_message('INFO', 
                    f'Message sent to service {service_name} (PID {service_info["pid"]}): {str(message)[:100]}...',
                    {'from_pid': pid}
                )
                
                return {
                    'success': True,
                    'service': service_name,
                    'target_pid': service_info['pid'],
                    'message': 'Message queued for delivery'
                }
        
        # Endpoint não encontrado
        else:
            return {'success': False, 'error': f'Unknown API endpoint: {endpoint}'}
    
    def _get_system_metrics(self):
        """Obtém métricas do sistema"""
        import psutil
        
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Conta processos do ambiente
            env_processes = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Verifica se o processo está no ambiente
                    # (simplificação - em implementação real verificar namespaces)
                    env_processes += 1
                except:
                    pass
            
            return {
                'success': True,
                'cpu_percent': cpu_percent,
                'memory_total': memory.total,
                'memory_available': memory.available,
                'memory_percent': memory.percent,
                'process_count': env_processes,
                'timestamp': time.time()
            }
        except:
            return {
                'success': True,
                'cpu_percent': 0,
                'process_count': len(self._env.process._processes),
                'timestamp': time.time()
            }
    
    def _log_message(self, level: str, message: str, extra: dict = None):
        """Registra mensagem de log interno"""
        log_entry = {
            'timestamp': time.time(),
            'level': level,
            'message': message,
            'extra': extra or {}
        }
        
        with self._api_lock:
            self._logs.append(log_entry)
            if len(self._logs) > 1000:
                self._logs = self._logs[-1000:]
    
    def stop_api_server(self):
        """Para o servidor da API"""
        # Implementação para parar o servidor
        pass

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import pyroute2
    PYROUTE2_AVAILABLE = True
except ImportError:
    PYROUTE2_AVAILABLE = False


class VirtualEnviron:
    """Main class for creating and managing virtual environments"""
    # o usuario pode usar mais foi feita uso interno
    class virtpy_lib:
        def __init__(self, env):
            self._env = env
        def set_libsandbox(self):
            lib_path = "/lib/libsandbox.so"
            if "LD_PRELOAD" in self._env.environ.to_dict():
                atual = self._env.environ.get("LD_PRELOAD")
                self._env.environ.set("LD_PRELOAD", atual + ":" + lib_path)
            else:
                self._env.environ.set("LD_PRELOAD", lib_path)
        def create_sandbox_preload(self, pid, chroot):
            source_code = f'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

// Configurações do sandbox
static const char *CHROOT_PATH = "{chroot}";
static const pid_t TARGET_PPID = {pid};

// Ponteiros para funções originais
static int (*original_open)(const char *pathname, int flags, ...) = NULL;
static int (*original_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static FILE *(*original_fopen)(const char *pathname, const char *mode) = NULL;
static DIR *(*original_opendir)(const char *name) = NULL;
static int (*original_stat)(const char *pathname, struct stat *statbuf) = NULL;
static int (*original_lstat)(const char *pathname, struct stat *statbuf) = NULL;
static int (*original_access)(const char *pathname, int mode) = NULL;
static int (*original_chdir)(const char *path) = NULL;
static int (*original_execve)(const char *pathname, char *const argv[], char *const envp[]) = NULL;
static pid_t (*original_fork)(void) = NULL;
static int (*original_kill)(pid_t pid, int sig) = NULL;
static pid_t (*original_getpid)(void) = NULL;
static pid_t (*original_getppid)(void) = NULL;

static char* redirect_path(const char *path) {{
    if (path == NULL) return NULL;
    
    static char new_path[4096];
    
    // Se for caminho absoluto
    if (path[0] == '/') {{
        snprintf(new_path, sizeof(new_path), "%s%s", CHROOT_PATH, path);
        return new_path;
    }}
    
    
    // Primeiro, vamos pegar o cwd REAL (já dentro do chroot)
    char cwd[2048];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {{
        // Fallback: assume raiz do chroot
        snprintf(new_path, sizeof(new_path), "%s/%s", CHROOT_PATH, path);
        return new_path;
    }}
    
    // BLOQUEIA tentativas de escape via ".."
    // Se tentar subir além da raiz do sandbox, fica na raiz
    if (!path || !strcmp(path, "..") || strstr(path, "../") || strstr(path, "/../") || (strlen(path) >= 2 && !strcmp(path + strlen(path) - 2, "/..")) || (!strncmp(path, "..", 2) && (!path[2] || path[2] == '/'))) {{
        // Verifica se já está na raiz do sandbox
        if (strcmp(cwd, CHROOT_PATH) == 0) {{
            // Já está na raiz, ".." permanece na raiz
            snprintf(new_path, sizeof(new_path), "%s/", CHROOT_PATH);
            return new_path;
        }} else {{
            // NÃO está na raiz - permite navegar para o diretório pai
            // dentro do sandbox
        
            // Encontra o último '/' no caminho atual
            char *last_slash = strrchr(cwd, '/');
        
            if (last_slash != NULL && last_slash > cwd) {{
                // Remove o último componente do caminho
                size_t parent_len = last_slash - cwd;
                strncpy(new_path, cwd, parent_len);
                new_path[parent_len] = '\\0';
    }} else {{
        // Já está no nível mais alto possível antes da raiz?
        // Por segurança, vai para a raiz do sandbox
        snprintf(new_path, sizeof(new_path), "%s", CHROOT_PATH);
        }}
        return new_path;
    }}
}}
    
    // cwd já está dentro do CHROOT_PATH, então usamos diretamente
    // Construímos: cwd + "/" + path
    // O Linux resolverá os "." e ".." automaticamente
    
    snprintf(new_path, sizeof(new_path), "%s/%s", cwd, path);
    return new_path;
}}

// Verifica se um processo está dentro do nosso sandbox
static int is_allowed_process(pid_t pid) {{
    if (pid <= 0) return 1; // Processos especiais do sistema
    
    // O próprio processo atual sempre permitido
    if (pid == getpid()) return 1;
    
    // Verifica se o processo é descendente do TARGET_PPID
    char status_path[256];
    char line[256];
    pid_t current_pid = pid;
    pid_t ppid;
    
    // Segue a árvore de processos
    while (current_pid > 1) {{
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", current_pid);
        FILE *fp = fopen(status_path, "r");
        if (!fp) return 0;
        
        ppid = 0;
        while (fgets(line, sizeof(line), fp)) {{
            if (strncmp(line, "PPid:", 5) == 0) {{
                sscanf(line + 5, "%d", &ppid);
                break;
            }}
        }}
        fclose(fp);
        
        if (ppid == 0) return 0;
        
        // Se encontramos o PPID alvo, é permitido
        if (ppid == TARGET_PPID || ppid == getpid()) return 1;
        
        // Se encontramos um processo fora da hierarquia, nega
        if (ppid == 1) return 0;
        
        current_pid = ppid;
    }}
    
    return 0;
}}

// Hook para open()
int open(const char *pathname, int flags, ...) {{
    if (!original_open) {{
        original_open = dlsym(RTLD_NEXT, "open");
    }}
    
    mode_t mode = 0;
    if (flags & O_CREAT) {{
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }}
    
    char *new_path = redirect_path(pathname);
    
    if (flags & O_CREAT) {{
        return original_open(new_path, flags, mode);
    }} else {{
        return original_open(new_path, flags);
    }}
}}

// Hook para openat()
int openat(int dirfd, const char *pathname, int flags, ...) {{
    if (!original_openat) {{
        original_openat = dlsym(RTLD_NEXT, "openat");
    }}
    
    mode_t mode = 0;
    if (flags & O_CREAT) {{
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }}
    
    char *new_path = redirect_path(pathname);
    
    if (flags & O_CREAT) {{
        return original_openat(dirfd, new_path, flags, mode);
    }} else {{
        return original_openat(dirfd, new_path, flags);
    }}
}}

// Hook para fopen()
FILE *fopen(const char *pathname, const char *mode) {{
    if (!original_fopen) {{
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }}
    
    char *new_path = redirect_path(pathname);
    return original_fopen(new_path, mode);
}}

// Hook para opendir()
DIR *opendir(const char *name) {{
    if (!original_opendir) {{
        original_opendir = dlsym(RTLD_NEXT, "opendir");
    }}
    
    char *new_path = redirect_path(name);
    return original_opendir(new_path);
}}

// Hook para stat()
int stat(const char *pathname, struct stat *statbuf) {{
    if (!original_stat) {{
        original_stat = dlsym(RTLD_NEXT, "stat");
    }}
    
    char *new_path = redirect_path(pathname);
    return original_stat(new_path, statbuf);
}}

// Hook para lstat()
int lstat(const char *pathname, struct stat *statbuf) {{
    if (!original_lstat) {{
        original_lstat = dlsym(RTLD_NEXT, "lstat");
    }}
    
    char *new_path = redirect_path(pathname);
    return original_lstat(new_path, statbuf);
}}

// Hook para access()
int access(const char *pathname, int mode) {{
    if (!original_access) {{
        original_access = dlsym(RTLD_NEXT, "access");
    }}
    
    char *new_path = redirect_path(pathname);
    return original_access(new_path, mode);
}}

// Hook para chdir()
int chdir(const char *path) {{
    if (!original_chdir) {{
        original_chdir = dlsym(RTLD_NEXT, "chdir");
    }}
    
    char *new_path = redirect_path(path);
    return original_chdir(new_path);
}}

// Hook para execve()
int execve(const char *pathname, char *const argv[], char *const envp[]) {{
    if (!original_execve) {{
        original_execve = dlsym(RTLD_NEXT, "execve");
    }}
    
    char *new_path = redirect_path(pathname);
    return original_execve(new_path, argv, envp);
}}

// Hook para fork() - garante que filhos herdem sandbox
pid_t fork(void) {{
    if (!original_fork) {{
        original_fork = dlsym(RTLD_NEXT, "fork");
    }}
    
    return original_fork();
}}

// Hook para kill() - impede matar processos fora do sandbox
int kill(pid_t pid, int sig) {{
    if (!original_kill) {{
        original_kill = dlsym(RTLD_NEXT, "kill");
    }}
    
    // Verifica se o processo alvo está dentro do sandbox
    if (!is_allowed_process(pid)) {{
        errno = EPERM;
        return -1;
    }}
    
    return original_kill(pid, sig);
}}

// Hook para getpid() - retorna PID virtual se necessário
pid_t getpid(void) {{
    if (!original_getpid) {{
        original_getpid = dlsym(RTLD_NEXT, "getpid");
    }}
    
    return original_getpid();
}}

// Hook para getppid() - retorna PPID virtual se necessário
pid_t getppid(void) {{
    if (!original_getppid) {{
        original_getppid = dlsym(RTLD_NEXT, "getppid");
    }}
    
    return original_getppid();
}}

// Inicialização sem chroot!
__attribute__((constructor))
static void init_sandbox() {{
    // Apenas muda para o diretório do sandbox (sem chroot)
    // Isso é seguro e não precisa de privilégios
    chdir(CHROOT_PATH);
    
    // Log opcional para debug
    char* debug = getenv("VIRTPY_DEBUG");
    if (debug != NULL && strcmp(debug, "1") == 0) {{
        fprintf(stderr, "[VirtPy] Sandbox loaded for PPID %d in %s\\n", 
                TARGET_PPID, CHROOT_PATH);
    }}
}}
'''
            a, b, c = self._env.library.create_lib("libsandbox", source_code)
            return {"sucess": a, "path": b, "msg": c}
        
        def create_libc_mini(self):
            source ="""
/* libc.so mini - Biblioteca C minimalista e funcional
 * Compilar: gcc -shared -fPIC -o libmini.so libmini.c -nostdlib -nodefaultlibs
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <stdatomic.h>

/* ============ SYSCALL WRAPPERS ============ */
#if defined(__x86_64__)
    #define SYSCALL_CLOBBERS "rcx", "r11", "memory"
#elif defined(__i386__)
    #define SYSCALL_CLOBBERS "memory"
#elif defined(__aarch64__)
    #define SYSCALL_CLOBBERS "memory"
#elif defined(__arm__)
    #define SYSCALL_CLOBBERS "memory"
#endif

static inline long syscall1(long n, long a1) {
    long ret;
#if defined(__x86_64__)
    register long rdi __asm__("rdi") = a1;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi) : SYSCALL_CLOBBERS);
#elif defined(__i386__)
    register long ebx __asm__("ebx") = a1;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "r"(ebx) : SYSCALL_CLOBBERS);
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a1;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x0), "r"(x8) : SYSCALL_CLOBBERS);
    ret = x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a1;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(n), "0"(r0) : SYSCALL_CLOBBERS);
    ret = r0;
#endif
    return ret;
}



static inline long syscall2(long n, long a1, long a2) {
    long ret;
#if defined(__x86_64__)
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi), "r"(rsi) : SYSCALL_CLOBBERS);
#elif defined(__i386__)
    register long ebx __asm__("ebx") = a1;
    register long ecx __asm__("ecx") = a2;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "r"(ebx), "r"(ecx) : SYSCALL_CLOBBERS);
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x8) : SYSCALL_CLOBBERS);
    ret = x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a1;
    register long r1 __asm__("r1") = a2;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(n), "0"(r0), "r"(r1) : SYSCALL_CLOBBERS);
    ret = r0;
#endif
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
#if defined(__x86_64__)
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi), "r"(rsi), "r"(rdx) : SYSCALL_CLOBBERS);
#elif defined(__i386__)
    register long ebx __asm__("ebx") = a1;
    register long ecx __asm__("ecx") = a2;
    register long edx __asm__("edx") = a3;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "r"(ebx), "r"(ecx), "r"(edx) : SYSCALL_CLOBBERS);
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : SYSCALL_CLOBBERS);
    ret = x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a1;
    register long r1 __asm__("r1") = a2;
    register long r2 __asm__("r2") = a3;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(n), "0"(r0), "r"(r1), "r"(r2) : SYSCALL_CLOBBERS);
    ret = r0;
#endif
    return ret;
}

/* ============ MEMORY FUNCTIONS ============ */
__attribute__((visibility("default")))
void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n-- > 0) *p++ = (unsigned char)c;
    return s;
}

__attribute__((visibility("default")))
void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n-- > 0) *d++ = *s++;
    return dest;
}

__attribute__((visibility("default")))
void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    
    if (d == s) return dest;
    if (d < s) return memcpy(dest, src, n);
    
    d += n;
    s += n;
    while (n-- > 0) *--d = *--s;
    return dest;
}

__attribute__((visibility("default")))
int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;
    while (n-- > 0) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

/* ============ STRING FUNCTIONS ============ */
__attribute__((visibility("default")))
size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

__attribute__((visibility("default")))
char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

__attribute__((visibility("default")))
char *strncpy(char *dest, const char *src, size_t n) {
    char *d = dest;
    while (n > 0 && (*d++ = *src++)) n--;
    while (n-- > 0) *d++ = '\0';
    return dest;
}

__attribute__((visibility("default")))
int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) s1++, s2++;
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

__attribute__((visibility("default")))
int strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    while (--n > 0 && *s1 && *s1 == *s2) s1++, s2++;
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

__attribute__((visibility("default")))
char *strcat(char *dest, const char *src) {
    char *d = dest;
    while (*d) d++;
    while ((*d++ = *src++));
    return dest;
}

__attribute__((visibility("default")))
char *strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return NULL;
}

__attribute__((visibility("default")))
char *strrchr(const char *s, int c) {
    const char *last = NULL;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    return (char *)last;
}

/* ============ MEMORY ALLOCATION ============ */
#define ALIGNMENT 16
#define CHUNK_OVERHEAD (sizeof(struct chunk))

struct chunk {
    size_t size;
    struct chunk *next;
    int free;
};

static struct chunk *free_list = NULL;
static _Atomic int heap_lock = 0;

static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static void *sbrk_increment(size_t size) {
    static void *heap_end = NULL;
    void *old_brk;
    
    if (!heap_end) {
        heap_end = (void *)syscall1(__NR_brk, 0);
    }
    
    old_brk = heap_end;
    void *new_brk = (char *)heap_end + size;
    
    if (syscall1(__NR_brk, (long)new_brk) != (long)new_brk) {
        return (void *)-1;
    }
    
    heap_end = new_brk;
    return old_brk;
}

__attribute__((visibility("default")))
void *malloc(size_t size) {
    if (size == 0) return NULL;
    
    size = align_size(size + CHUNK_OVERHEAD);
    
    // Lock para thread safety
    while (__sync_lock_test_and_set(&heap_lock, 1)) {
        // Spin
    }
    
    // Procurar chunk livre
    struct chunk *chunk = free_list;
    struct chunk *prev = NULL;
    
    while (chunk) {
        if (chunk->free && chunk->size >= size) {
            chunk->free = 0;
            
            // Dividir chunk se for grande o suficiente
            if (chunk->size >= size + CHUNK_OVERHEAD + ALIGNMENT) {
                struct chunk *new_chunk = (struct chunk *)((char *)chunk + size);
                new_chunk->size = chunk->size - size;
                new_chunk->free = 1;
                new_chunk->next = chunk->next;
                
                chunk->size = size;
                chunk->next = new_chunk;
            }
            
            __sync_lock_release(&heap_lock);
            return (void *)(chunk + 1);
        }
        prev = chunk;
        chunk = chunk->next;
    }
    
    // Alocar novo chunk
    chunk = (struct chunk *)sbrk_increment(size);
    if (chunk == (void *)-1) {
        __sync_lock_release(&heap_lock);
        return NULL;
    }
    
    chunk->size = size;
    chunk->free = 0;
    chunk->next = NULL;
    
    if (prev) prev->next = chunk;
    else free_list = chunk;
    
    __sync_lock_release(&heap_lock);
    return (void *)(chunk + 1);
}

__attribute__((visibility("default")))
void free(void *ptr) {
    if (!ptr) return;
    
    struct chunk *chunk = (struct chunk *)ptr - 1;
    
    while (__sync_lock_test_and_set(&heap_lock, 1)) {
        // Spin
    }
    
    chunk->free = 1;
    
    // Coalescing com próximo
    if (chunk->next && chunk->next->free) {
        chunk->size += chunk->next->size;
        chunk->next = chunk->next->next;
    }
    
    __sync_lock_release(&heap_lock);
}

__attribute__((visibility("default")))
void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

__attribute__((visibility("default")))
void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    struct chunk *chunk = (struct chunk *)ptr - 1;
    size_t old_size = chunk->size - CHUNK_OVERHEAD;
    
    if (old_size >= size) {
        return ptr;
    }
    
    void *new_ptr = malloc(size);
    if (!new_ptr) return NULL;
    
    memcpy(new_ptr, ptr, old_size);
    free(ptr);
    return new_ptr;
}

/* ============ I/O FUNCTIONS ============ */
__attribute__((visibility("default")))
int write(int fd, const void *buf, size_t count) {
    long ret = syscall3(__NR_write, fd, (long)buf, count);
    if (ret < 0) {
        return -1;
    }
    return (int)ret;
}

__attribute__((visibility("default")))
int read(int fd, void *buf, size_t count) {
    long ret = syscall3(__NR_read, fd, (long)buf, count);
    if (ret < 0) {
        return -1;
    }
    return (int)ret;
}

__attribute__((visibility("default")))
int open(const char *pathname, int flags, ...) {
    // Modo padrão se não fornecido
    mode_t mode = 0;
    if (flags & O_CREAT) {
        // Para va_args
        __builtin_va_list ap;
        __builtin_va_start(ap, flags);
        mode = __builtin_va_arg(ap, mode_t);
        __builtin_va_end(ap);
    }
    
    long ret = syscall3(__NR_open, (long)pathname, flags, mode);
    if (ret < 0) {
        return -1;
    }
    return (int)ret;
}

__attribute__((visibility("default")))
int close(int fd) {
    long ret = syscall1(__NR_close, fd);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

__attribute__((visibility("default")))
off_t lseek(int fd, off_t offset, int whence) {
    long ret = syscall3(__NR_lseek, fd, offset, whence);
    if (ret < 0) {
        return -1;
    }
    return (off_t)ret;
}

__attribute__((visibility("default")))
void exit(int status) {
    syscall1(__NR_exit_group, status);
    while (1); // Nunca retorna
}

/* ============ ENVIRONMENT ============ */
static __thread int errno_value = 0;

__attribute__((visibility("default")))
int *__errno_location(void) {
    return &errno_value;
}

/* ============ FILE OPERATIONS ============ */
__attribute__((visibility("default")))
int fstat(int fd, struct stat *statbuf) {
    long ret = syscall2(__NR_fstat, fd, (long)statbuf);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

/* ============ MEMORY MAPPING ============ */
__attribute__((visibility("default")))
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    long ret = syscall6(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
    if (ret < 0 && ret > -4096) {
        return MAP_FAILED;
    }
    return (void *)ret;
}

__attribute__((visibility("default")))
int munmap(void *addr, size_t length) {
    long ret = syscall2(__NR_munmap, (long)addr, length);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

/* syscall6 para x86_64 */
#if defined(__x86_64__)
static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}
#else
static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    // Implementação genérica usando mmap2 para arquiteturas 32-bit
    if (n == __NR_mmap) {
        // Em sistemas 32-bit, offset é em páginas
        return syscall3(__NR_mmap2, a1, a2, a3, a4, a5, a6 >> 12);
    }
    // Fallback
    return -ENOSYS;
}
#endif
"""
            a, b, c = self._env.library.create_lib("libc", source)
            return {"sucess": a, "path": b, "msg": c}
            
        def create_libm_mini(self):
            source = """
/* libm.so mini- Biblioteca matemática minimalista
 * Compilar: gcc -shared -fPIC -o libminim.so libminim.c
 */

#include <stdint.h>

/* ============ CONSTANTES ============ */
static const double PI = 3.14159265358979323846;
static const double E = 2.71828182845904523536;
static const double LN2 = 0.69314718055994530942;

/* ============ FUNÇÕES BÁSICAS ============ */
__attribute__((visibility("default")))
double fabs(double x) {
    union { double f; uint64_t i; } u = {x};
    u.i &= 0x7fffffffffffffffULL;
    return u.f;
}

__attribute__((visibility("default")))
float fabsf(float x) {
    union { float f; uint32_t i; } u = {x};
    u.i &= 0x7fffffff;
    return u.f;
}

__attribute__((visibility("default")))
double sqrt(double x) {
    if (x < 0.0) return 0.0;
    if (x == 0.0) return 0.0;
    
    double y = x;
    double z = 0.0;
    
    // Método de Newton-Raphson
    for (int i = 0; i < 20; i++) {
        z = (y + x / y) * 0.5;
        if (fabs(y - z) < 1e-15) break;
        y = z;
    }
    return z;
}

/* ============ FUNÇÕES EXPONENCIAIS ============ */
__attribute__((visibility("default")))
double exp(double x) {
    // Handle special cases
    if (x == 0.0) return 1.0;
    if (x > 709.0) return 1.0/0.0; // Infinity
    if (x < -709.0) return 0.0;
    
    // Range reduction: e^x = 2^(x/ln(2))
    double z = x / LN2;
    int n = (int)z;
    double r = z - n;
    
    // Polynomial approximation for 2^r
    double p = 1.0 + r * (0.999999999999999 + r * (0.499999999999999 + 
                r * (0.166666666666667 + r * (0.041666666666667 + 
                r * (0.008333333333333 + r * (0.001388888888889 + 
                r * (0.000198412698413 + r * (0.000024801587302))))))));
    
    // Scale by 2^n
    union { double f; uint64_t i; } u;
    n += 1023; // Bias for double exponent
    u.i = (uint64_t)n << 52;
    
    return p * u.f;
}

__attribute__((visibility("default")))
double log(double x) {
    if (x <= 0.0) return -1.0/0.0; // -Infinity
    
    // Range reduction
    int e = 0;
    while (x >= 2.0) { x /= 2.0; e++; }
    while (x < 1.0) { x *= 2.0; e--; }
    
    x -= 1.0;
    
    // Polynomial approximation
    double z = x;
    double y = x;
    double x2 = x * x;
    
    y += z * x2 * (1.0/3.0);
    z *= x2;
    y += z * x2 * (1.0/5.0);
    z *= x2;
    y += z * x2 * (1.0/7.0);
    z *= x2;
    y += z * x2 * (1.0/9.0);
    z *= x2;
    y += z * x2 * (1.0/11.0);
    
    return y + e * LN2;
}

__attribute__((visibility("default")))
double pow(double x, double y) {
    if (y == 0.0) return 1.0;
    if (x == 0.0) return 0.0;
    if (y == 1.0) return x;
    
    // x^y = exp(y * log(x))
    return exp(y * log(x));
}

/* ============ FUNÇÕES TRIGONOMÉTRICAS ============ */
__attribute__((visibility("default")))
double sin(double x) {
    // Range reduction to [-π, π]
    x = x - (2.0 * PI) * ((int)((x + PI) / (2.0 * PI)));
    
    // Polynomial approximation (minimax)
    double x2 = x * x;
    double result = x * (1.0 + x2 * (-1.0/6.0 + x2 * (1.0/120.0 + 
                       x2 * (-1.0/5040.0 + x2 * (1.0/362880.0)))));
    
    return result;
}

__attribute__((visibility("default")))
double cos(double x) {
    // cos(x) = sin(π/2 - x)
    return sin(PI/2.0 - x);
}

__attribute__((visibility("default")))
double tan(double x) {
    double c = cos(x);
    if (c == 0.0) return 0.0; // Evita divisão por zero
    return sin(x) / c;
}

/* ============ FUNÇÕES DE ARREDONDAMENTO ============ */
__attribute__((visibility("default")))
double floor(double x) {
    if (x >= 0.0) {
        int64_t n = (int64_t)x;
        return (double)n;
    } else {
        int64_t n = (int64_t)x;
        if ((double)n == x) return x;
        return (double)(n - 1);
    }
}

__attribute__((visibility("default")))
double ceil(double x) {
    if (x <= 0.0) {
        int64_t n = (int64_t)x;
        return (double)n;
    } else {
        int64_t n = (int64_t)x;
        if ((double)n == x) return x;
        return (double)(n + 1);
    }
}

__attribute__((visibility("default")))
double trunc(double x) {
    return (x >= 0.0) ? floor(x) : ceil(x);
}

__attribute__((visibility("default")))
double round(double x) {
    if (x >= 0.0) {
        return floor(x + 0.5);
    } else {
        return ceil(x - 0.5);
    }
}

/* ============ FUNÇÕES HIPERBÓLICAS ============ */
__attribute__((visibility("default")))
double sinh(double x) {
    double ex = exp(x);
    double emx = exp(-x);
    return (ex - emx) * 0.5;
}

__attribute__((visibility("default")))
double cosh(double x) {
    double ex = exp(x);
    double emx = exp(-x);
    return (ex + emx) * 0.5;
}

__attribute__((visibility("default")))
double tanh(double x) {
    if (x > 20.0) return 1.0;
    if (x < -20.0) return -1.0;
    
    double ex = exp(x);
    double emx = exp(-x);
    return (ex - emx) / (ex + emx);
}

/* ============ FUNÇÕES INVERSAS ============ */
__attribute__((visibility("default")))
double asin(double x) {
    if (x < -1.0 || x > 1.0) return 0.0;
    
    // asin(x) ≈ x + x³/6 + 3x⁵/40 + 5x⁷/112
    double x2 = x * x;
    double result = x;
    double term = x;
    
    term *= x2 * (1.0/6.0);
    result += term;
    term *= x2 * (3.0/5.0);
    result += term;
    term *= x2 * (5.0/7.0);
    result += term;
    
    return result;
}

__attribute__((visibility("default")))
double acos(double x) {
    // acos(x) = π/2 - asin(x)
    return PI/2.0 - asin(x);
}

__attribute__((visibility("default")))
double atan(double x) {
    if (x == 0.0) return 0.0;
    if (x == 1.0) return PI/4.0;
    if (x == -1.0) return -PI/4.0;
    
    // Range reduction
    int sign = 1;
    if (x < 0.0) {
        x = -x;
        sign = -1;
    }
    
    double result;
    if (x > 1.0) {
        result = PI/2.0 - atan(1.0/x);
    } else {
        double x2 = x * x;
        result = x * (1.0 - x2 * (1.0/3.0 - x2 * (1.0/5.0 - 
                      x2 * (1.0/7.0 - x2 * (1.0/9.0)))));
    }
    
    return sign * result;
}

__attribute__((visibility("default")))
double atan2(double y, double x) {
    if (x > 0.0) {
        return atan(y / x);
    } else if (x < 0.0) {
        if (y >= 0.0) {
            return atan(y / x) + PI;
        } else {
            return atan(y / x) - PI;
        }
    } else {
        if (y > 0.0) return PI/2.0;
        if (y < 0.0) return -PI/2.0;
        return 0.0;
    }
}
"""
            a, b, c = self._env.library.create_lib("libm", source)
            return {"sucess": a, "path": b, "msg": c}
        def create_libpth_mini(self):
            source = """
/* libpthread.so mini - Implementação básica de pthreads
 * Compilar: gcc -shared -fPIC -o libminipthread.so libminipthread.c -lpthread
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stddef.h>
#include <stdatomic.h>
#include <linux/futex.h>

/* ============ STRUCTS E DEFINIÇÕES ============ */
typedef int pthread_t;
typedef struct {
    _Atomic int lock;
    int type;
    int recursive;
    _Atomic int owner;
    _Atomic int count;
} pthread_mutex_t;

typedef int pthread_attr_t;
typedef int pthread_mutexattr_t;

struct thread_info {
    void *(*start_routine)(void *);
    void *arg;
    void *result;
    int detached;
    int joined;
    pthread_t id;
    pid_t tid;
    _Atomic int state;
};

/* ============ SYSCALL HELPERS ============ */
static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
#if defined(__x86_64__)
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
#elif defined(__i386__)
    register long ebx __asm__("ebx") = a1;
    register long ecx __asm__("ecx") = a2;
    register long edx __asm__("edx") = a3;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "r"(ebx), "r"(ecx), "r"(edx) : "memory");
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
    ret = x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a1;
    register long r1 __asm__("r1") = a2;
    register long r2 __asm__("r2") = a3;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(n), "0"(r0), "r"(r1), "r"(r2) : "memory");
    ret = r0;
#endif
    return ret;
}

static inline long syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;
#if defined(__x86_64__)
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
#else
    // Fallback para outras arquiteturas
    ret = -1;
#endif
    return ret;
}

/* ============ THREAD FUNCTIONS ============ */
static int thread_start(void *arg) {
    struct thread_info *info = (struct thread_info *)arg;
    
    info->state = 1; // Running
    info->result = info->start_routine(info->arg);
    info->state = 2; // Terminated
    
    if (info->detached) {
        // Auto-cleanup para threads detached
        // Liberar memória (implementação simplificada)
    }
    
    syscall3(__NR_exit, 0, 0, 0);
    return 0;
}

__attribute__((visibility("default")))
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    (void)attr; // Atributos não usados nesta implementação básica
    
    // Alocar estrutura de thread
    struct thread_info *info = (struct thread_info *)malloc(sizeof(struct thread_info));
    if (!info) return -1;
    
    info->start_routine = start_routine;
    info->arg = arg;
    info->detached = 0;
    info->joined = 0;
    info->state = 0;
    
    static _Atomic int next_id = 1;
    info->id = __atomic_fetch_add(&next_id, 1, __ATOMIC_SEQ_CST);
    
    // Flags para clone()
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
                CLONE_CHILD_CLEARTID;
    
    // Alocar stack
    size_t stack_size = 2 * 1024 * 1024; // 2MB
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    
    if (stack == MAP_FAILED) {
        free(info);
        return -1;
    }
    
    char *stack_top = (char *)stack + stack_size;
    pid_t tid = syscall5(__NR_clone, flags, (long)stack_top, 0, (long)&info->tid, 0);
    
    if (tid < 0) {
        munmap(stack, stack_size);
        free(info);
        return -1;
    }
    
    if (tid == 0) {
        // Thread filha
        thread_start(info);
    }
    
    info->tid = tid;
    *thread = info->id;
    
    return 0;
}

__attribute__((visibility("default")))
int pthread_join(pthread_t thread, void **retval) {
    (void)thread;
    (void)retval;
    
    // Implementação simplificada: busy wait
    // Em implementação real, usaria futex
    for (volatile int i = 0; i < 1000000; i++);
    
    return 0;
}

__attribute__((visibility("default")))
int pthread_detach(pthread_t thread) {
    (void)thread;
    // Marcar thread como detached
    return 0;
}

__attribute__((visibility("default")))
pthread_t pthread_self(void) {
    return (pthread_t)syscall3(__NR_gettid, 0, 0, 0);
}

/* ============ MUTEX FUNCTIONS ============ */
__attribute__((visibility("default")))
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    (void)attr;
    
    mutex->lock = 0;
    mutex->type = 0; // Normal mutex
    mutex->recursive = 0;
    mutex->owner = 0;
    mutex->count = 0;
    
    return 0;
}

__attribute__((visibility("default")))
int pthread_mutex_lock(pthread_mutex_t *mutex) {
    int tid = (int)syscall3(__NR_gettid, 0, 0, 0);
    
    if (mutex->recursive && mutex->owner == tid) {
        __atomic_fetch_add(&mutex->count, 1, __ATOMIC_SEQ_CST);
        return 0;
    }
    
    while (1) {
        int expected = 0;
        if (__atomic_compare_exchange_n(&mutex->lock, &expected, 1, 
                                        0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            mutex->owner = tid;
            mutex->count = 1;
            return 0;
        }
        
        // Futex wait
        syscall3(__NR_futex, (long)&mutex->lock, FUTEX_WAIT, 1);
    }
}

__attribute__((visibility("default")))
int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    int tid = (int)syscall3(__NR_gettid, 0, 0, 0);
    
    if (mutex->owner != tid) {
        return -1; // Não é o dono
    }
    
    if (mutex->recursive) {
        int count = __atomic_fetch_sub(&mutex->count, 1, __ATOMIC_SEQ_CST) - 1;
        if (count > 0) {
            return 0;
        }
    }
    
    mutex->owner = 0;
    __atomic_store_n(&mutex->lock, 0, __ATOMIC_RELEASE);
    
    // Futex wake
    syscall3(__NR_futex, (long)&mutex->lock, FUTEX_WAKE, 1);
    
    return 0;
}

__attribute__((visibility("default")))
int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

__attribute__((visibility("default")))
int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    int tid = (int)syscall3(__NR_gettid, 0, 0, 0);
    
    if (mutex->recursive && mutex->owner == tid) {
        __atomic_fetch_add(&mutex->count, 1, __ATOMIC_SEQ_CST);
        return 0;
    }
    
    int expected = 0;
    if (__atomic_compare_exchange_n(&mutex->lock, &expected, 1, 
                                    0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        mutex->owner = tid;
        mutex->count = 1;
        return 0;
    }
    
    return -1; // Busy
}

/* ============ CONDITION VARIABLES (SIMPLIFICADO) ============ */
typedef struct {
    _Atomic int waiters;
    _Atomic int wakeups;
} pthread_cond_t;

__attribute__((visibility("default")))
int pthread_cond_init(pthread_cond_t *cond, const void *attr) {
    (void)attr;
    cond->waiters = 0;
    cond->wakeups = 0;
    return 0;
}

__attribute__((visibility("default")))
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    __atomic_fetch_add(&cond->waiters, 1, __ATOMIC_SEQ_CST);
    pthread_mutex_unlock(mutex);
    
    // Wait usando futex
    while (__atomic_load_n(&cond->wakeups, __ATOMIC_ACQUIRE) == 0) {
        syscall3(__NR_futex, (long)&cond->wakeups, FUTEX_WAIT, 0);
    }
    
    __atomic_fetch_sub(&cond->wakeups, 1, __ATOMIC_SEQ_CST);
    pthread_mutex_lock(mutex);
    
    return 0;
}

__attribute__((visibility("default")))
int pthread_cond_signal(pthread_cond_t *cond) {
    if (__atomic_load_n(&cond->waiters, __ATOMIC_ACQUIRE) > 0) {
        __atomic_fetch_add(&cond->wakeups, 1, __ATOMIC_SEQ_CST);
        syscall3(__NR_futex, (long)&cond->wakeups, FUTEX_WAKE, 1);
    }
    return 0;
}

__attribute__((visibility("default")))
int pthread_cond_broadcast(pthread_cond_t *cond) {
    int waiters = __atomic_load_n(&cond->waiters, __ATOMIC_ACQUIRE);
    if (waiters > 0) {
        __atomic_store_n(&cond->wakeups, waiters, __ATOMIC_RELEASE);
        syscall3(__NR_futex, (long)&cond->wakeups, FUTEX_WAKE, waiters);
    }
    return 0;
}

__attribute__((visibility("default")))
int pthread_cond_destroy(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}
"""
            a, b, c = self._env.library.create_lib("libpthread", source)
            return {"sucess": a, "path": b, "msg": c}
    class Fs:
        """Virtual Filesystem manager"""
        
        def __init__(self, environ_instance: 'VirtualEnviron'):
            self._env = environ_instance
            self._base_path = environ_instance._base_path
            self._setup_fs()
        
        def import_from_host(self, host_path: str, virtual_path: str = None):
            """
            Import file/directory from REAL HOST into virtual environment
        
            Args:
                host_path: Path on real host filesystem
                virtual_path: Destination inside virtual environment (default: same name in /)
             There is no security because if the user wants to expose their environment to sabotage, that's their problem.
               """
            # Validate host path exists
            if not os.path.exists(host_path):
                raise FileNotFoundError(f"Host path not found: {host_path}")
        
            # Determine destination
            if virtual_path is None:
                # Use same name in root of virtual env
                filename = os.path.basename(host_path)
                virtual_path = f"/{filename}"
        
            # Convert to full virtual path
            dest_path = self._to_virtual_path(virtual_path)
        
            # Create parent directory if needed
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
            # Copy file or directory
            if os.path.isdir(host_path):
                shutil.copytree(host_path, dest_path, dirs_exist_ok=True)
            else:
                shutil.copy2(host_path, dest_path)
        
            return virtual_path
    
        def export_to_host(self, virtual_path: str, host_path: str = None):
            """
            Export file/directory from virtual environment to host
        
            Args:
            virtual_path: Path inside virtual environment
            host_path: Destination on host (default: current directory with same name)
            """
            # Get source path in virtual env
            source_path = self._to_virtual_path(virtual_path)
        
            if not os.path.exists(source_path):
                raise FileNotFoundError(f"Virtual path not found: {virtual_path}")
        
            # Determine destination
            if host_path is None:
                filename = os.path.basename(virtual_path)
                host_path = os.path.join(os.getcwd(), filename)
        
            # Copy
            if os.path.isdir(source_path):
                shutil.copytree(source_path, host_path, dirs_exist_ok=True)
            else:
                shutil.copy2(source_path, host_path)
        
            return host_path
        
        def _setup_fs(self):
            """Initialize virtual filesystem structure"""
            os.makedirs(self._base_path, exist_ok=True)
            dirs = ["bin", "lib", "usr/bin", "usr/sbin", "usr/lib"] 
            for d in dirs:
                os.makedirs(os.path.join(self._base_path, d), exist_ok=True)
            if self._env.create_opt:
                os.makedirs(os.path.join(self._base_path, "opt"), exist_ok = True)
            
            
            
            # Install basic Python in the environment
            self._install_python()
            self._install_sh()
            if self._env.install_pkm:
                self._install_package_manager
        def _install_sh(self):
            if shutil.which("sh"): 
                self.import_from_host(shutil.which("sh"), '/bin/sh')
        def _install_package_manager(self):
            pkms = ["apt", "apk", "pkg", "pacman", "dnf"]
            for pkm in pkms:
                if shutil.which(pkm): 
                    self.import_from_host(shutil.which(pkm), self._env.environ.get("PATH", "/bin").split(":")[0].replace(self._env._base_path, ""))
                    break
                else:
                    continue
                
        def _create_etc_files(self):
            pass # deixe o firejail criar
        
        def _install_python(self):
            """Install Python interpreter in the environment"""
            # Create symbolic links to system Python (or copy if needed)
            bin_path = os.path.join(self._base_path, 'bin')
            python_path = shutil.which('python3') or shutil.which('python')
            
            if python_path:
                target_path = os.path.join(bin_path, 'python3')
                if not os.path.exists(target_path):
                    shutil.copy(python_path, target_path)
                    os.chmod(target_path, 0o755)
                
        
        def mkdir(self, path: str, mode: int = 0o777, parents: bool = False):
            """Create directory in virtual filesystem"""
            full_path = self._to_virtual_path(path)
            if parents:
                os.makedirs(full_path, mode=mode, exist_ok=True)
            else:
                os.mkdir(full_path, mode=mode)
            return full_path
        
        def rmdir(self, path: str):
            """Remove empty directory from virtual filesystem"""
            full_path = self._to_virtual_path(path)
            os.rmdir(full_path)
        
        def remove(self, path: str):
            """Remove file from virtual filesystem"""
            full_path = self._to_virtual_path(path)
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
            else:
                os.remove(full_path)
        
        def exists(self, path: str) -> bool:
            """Check if path exists in virtual filesystem"""
            full_path = self._to_virtual_path(path)
            return os.path.exists(full_path)
        
        def isfile(self, path: str) -> bool:
            """Check if path is a file"""
            full_path = self._to_virtual_path(path)
            return os.path.isfile(full_path)
        
        def isdir(self, path: str) -> bool:
            """Check if path is a directory"""
            full_path = self._to_virtual_path(path)
            return os.path.isdir(full_path)
        
        def read(self, path: str, mode: str = 'r', encoding: Optional[str] = None):
            """Read file from virtual filesystem"""
            full_path = self._to_virtual_path(path)
            if 'b' in mode:
                with open(full_path, mode) as f:
                    return f.read()
            else:
                with open(full_path, mode, encoding=encoding) as f:
                    return f.read()
        
        def write(self, path: str, content: Any, mode: str = 'w', encoding: Optional[str] = None):
            """Write file to virtual filesystem"""
            full_path = self._to_virtual_path(path)
            dirname = os.path.dirname(full_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            
            if isinstance(content, bytes) or 'b' in mode:
                with open(full_path, mode) as f:
                    f.write(content)
            else:
                with open(full_path, mode, encoding=encoding) as f:
                    f.write(content)
        
        def listdir(self, path: str = '/') -> List[str]:
            """List directory contents"""
            full_path = self._to_virtual_path(path)
            return os.listdir(full_path)
        
        def walk(self, path: str = '/'):
            """Walk directory tree"""
            full_path = self._to_virtual_path(path)
            for root, dirs, files in os.walk(full_path):
                virtual_root = root[len(self._base_path):]
                if not virtual_root:
                    virtual_root = '/'
                yield virtual_root, dirs, files
        
        def stat(self, path: str):
            """Get file status"""
            full_path = self._to_virtual_path(path)
            return os.stat(full_path)
        
        def chmod(self, path: str, mode: int):
            """Change file mode"""
            full_path = self._to_virtual_path(path)
            os.chmod(full_path, mode)
        
        def chown(self, path: str, uid: int, gid: int):
            """Change file owner"""
            full_path = self._to_virtual_path(path)
            os.chown(full_path, uid, gid)
        
        def symlink(self, src: str, dst: str):
            """Create symbolic link"""
            dst_path = self._to_virtual_path(dst)
            src_path = self._to_virtual_path(src) if src.startswith('/') else src
            os.symlink(src_path, dst_path)
        
        def copy(self, src: str, dst: str):
            """Copy file or directory"""
            src_path = self._to_virtual_path(src) if src.startswith('/') else src
            dst_path = self._to_virtual_path(dst)
            
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
        
        def move(self, src: str, dst: str):
            """Move/rename file or directory"""
            src_path = self._to_virtual_path(src)
            dst_path = self._to_virtual_path(dst)
            shutil.move(src_path, dst_path)
        
        def _to_virtual_path(self, path: str) -> str:
            """Convert virtual path to real path WITH SAFETY"""
            # Normalize path
            if not path.startswith('/'):
                path = '/' + path
    
            # Clean up .. and .
            normalized = os.path.normpath(path)
    
            # SECURITY: Prevent directory traversal
            base = os.path.abspath(self._base_path)
            full_path = os.path.join(base, normalized.lstrip('/'))
            
            try:
                # O_NOFOLLOW previne seguir symlinks
                fd = os.open(full_path, os.O_RDONLY | os.O_NOFOLLOW)
                os.close(fd)
            except OSError as e:
                if e.errno == errno.ELOOP and os.realpath(full_path).split("/")[-1] != self._env._base_path.split("/")[-1] and "python" not in os.realpath(full_path):  # É perigoso
                    raise SecurityError(f"escape Symlink not allowed: {path}")
        
    
            # Ensure we don't escape the base directory
            if not os.path.commonpath([base, os.path.abspath(full_path)]) == base:
                raise SecurityError(f"Attempted directory traversal: {path}")
    
            return full_path
            
            # não tem acesso aos diretorios do sistema real e nao tem chance de symlink perigoso
        
        def get_size(self, path: str) -> int:
            """Get file/directory size in bytes"""
            full_path = self._to_virtual_path(path)
            if os.path.isfile(full_path):
                return os.path.getsize(full_path)
            elif os.path.isdir(full_path):
                total = 0
                for dirpath, dirnames, filenames in os.walk(full_path):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        total += os.path.getsize(fp)
                return total
            return 0
    
    class Environ:
        """Virtual Environment variables manager"""
        
        def __init__(self, environ_instance: 'VirtualEnviron'):
            self._env = environ_instance
            self._vars = environ_instance.vars.copy()
            self._load_system_vars()
        
        def _load_system_vars(self):
            """Load initial environment variables"""
            # Basic environment variables
            self._vars.update({
                'PATH': os.path.join(self._env._base_path, 'bin') + ":" + os.path.join(self._env._base_path, 'usr/bin') + ":" + os.path.join(self._env._base_path, 'usr/sbin'),
                'USER': "vuser",
                'LOGNAME': "vuser",
                'SHELL': 'undefined',
                'PWD': self._env._base_path,
                'VIRTPY_ENV': self._env.name,
                'LD_LIBRARY_PATH': os.path.join(self._env._base_path, "lib") + ":" + os.path.join(self._env._base_path, 'usr/lib'), # importante, processos dentro do ambiente virtual não tem acesso as bibliotecas do host, apenas as bibliotecas do ambiente, nao importe o que voce faca
                'VIRTPY_BASE': self._env._base_path,
            })
            
            # Add Python-specific variables
            python_path = os.path.join(self._env._base_path, 'lib', 'python3')
            self._vars['PYTHONPATH'] = python_path
            self._vars["PYTHONHOME"] = self._env._base_path
        
        def get(self, key: str, default: Any = None) -> Any:
            """Get environment variable"""
            return self._vars.get(key, default)
        
        def set(self, key: str, value: Any):
            """Set environment variable"""
            if key in ["PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "LD_PRELOAD", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "PKG_CONFIG_PATH", "MANPATH", "INFOPATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP", "PYTHONCASEOK", "JAVA_HOME", "CLASSPATH", "NODE_PATH", "NPM_CONFIG_PREFIX", "GOPATH", "GOROOT", "GEM_PATH", "GEM_HOME", "RUBYLIB", "RUBYPATH", "PERL5LIB", "PERLLIB", "CARGO_HOME", "RUSTUP_HOME", "PHPRC", "LUA_PATH", "LUA_CPATH", "CMAKE_PREFIX_PATH", "ACLOCAL_PATH", "ANDROID_SDK_ROOT", "ANDROID_HOME", "ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "GRADLE_USER_HOME"]:
                a = value.split(":")
                path = ":".join([p.replace("/", "", 1) for p in a])
                self._vars[key] = os.path.join(self._env._base_path, str(path))
                return
            self._vars[key] = str(value)
        
        def unset(self, key: str):
            """Unset environment variable"""
            if key in self._vars:
                del self._vars[key]
        
        def update(self, vars_dict: Dict[str, Any]):
            """Update multiple environment variables"""
            for a, b in vars_dict.items():
                self.set(a, b)
        
        def items(self):
            """Get all environment variables as items"""
            return self._vars.items()
        
        def keys(self):
            """Get all environment variable keys"""
            return self._vars.keys()
        
        def values(self):
            """Get all environment variable values"""
            return self._vars.values()
        
        def to_dict(self) -> Dict[str, str]:
            """Convert to dictionary"""
            return self._vars.copy()
        
        def clear(self):
            self._vars = {}
            self._load_system_vars()
        def zero(self):
            self._vars = {}
        def replace(self, vars: Dict[str, str]):
            self.zero()
            for a, b in vars.items():
                self.set(a, b)
        
        def load_from_file(self, path: str):
            """Load environment variables from file"""
            full_path = self._env.fs._to_virtual_path(path)
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            self._vars[key.strip()] = value.strip()
    
    class Process:
        """Virtual Process manager"""
        
        def __init__(self, environ_instance: 'VirtualEnviron'):
            self._env = environ_instance
            self._processes = {}  # pid -> subprocess.Popen
            self._next_pid = 1000
            self._lock = threading.Lock()
            
            # Setup process redirection
            self._setup_redirection()
        
        def _setup_redirection(self):
            """Setup process execution redirection"""
            # This would be implemented with Linux namespaces in a real implementation
            # For now, we'll use chroot and environment isolation
            pass
        def _find_command_in_path(self, command_name: str, env_vars: Dict[str, str]) -> Optional[str]:
            """
Procura um comando nos diretórios do PATH.
Retorna o caminho completo se encontrar.
            """
            # Obtém PATH das variáveis de ambiente
            path_dirs = env_vars.get('PATH', '').split(':')
    
            # Procura em cada diretório do PATH
            for path_dir in path_dirs:
                # Tenta com extensão .py
                py_cmd = os.path.join(path_dir, f"{command_name}.py")
                if os.path.exists(py_cmd) and os.access(py_cmd, os.X_OK):
                    return py_cmd
        
                # Tenta sem extensão
                cmd = os.path.join(path_dir, command_name)
                if os.path.exists(cmd) and os.access(cmd, os.X_OK):
                    return cmd
    
            return None
        


        def run(self, command: Union[str, List[str]],
                cwd: Optional[str] = None,
                env: Optional[Dict[str, str]] = None,
                input_data: Optional[bytes] = None,
                capture_output: bool = False,
                shell: bool = False) -> 'subprocess.Popen':
            firejail_path = shutil.which("firejail")
            namespace_name = f"virtpy_{self._env.name}"

            # Prepare environment
            process_env = self._env.environ.to_dict()
            if env:
                process_env.update(env)

            # USE_DEFAULT_COMMAND logic
            use_default_command = process_env.get('USE_DEFAULT_COMMAND', 'true').lower() == 'true'

            # Prepare command
            if isinstance(command, str) and not shell:
                command_parts = command.split()
            elif isinstance(command, list):
                command_parts = command.copy()
            else:
                command_parts = [command]

            if not use_default_command and command_parts:
                first_cmd = command_parts[0]
                if not first_cmd.startswith(('/', '.', '~')) and '/' not in first_cmd:
                    found_cmd = self._find_command_in_path(first_cmd, process_env)
                    if found_cmd:
                        command_parts[0] = found_cmd
                        if found_cmd.endswith('.py'):
                            command_parts = ['python'] + command_parts

            command = command_parts

            # Prepare working directory
            if cwd:
                real_cwd = self._env.fs._to_virtual_path(cwd)            
            else:
                real_cwd = self._env._base_path

            # Create pipes
            stdin = subprocess.PIPE if input_data is not None else None
            stdout = subprocess.PIPE if capture_output else None
            stderr = subprocess.PIPE if capture_output else subprocess.STDOUT

            try:
                # Run with chroot isolation
                if isinstance(command, str):
                    if any(b in command for b in [";", "&&", "||", "&", "$(", "`", "|", "${"]):
                        raise SecurityError("illegal char")
                elif isinstance(command, list):
                    for item in command:
                        if any(b in item for b in [";", "&&", "||", "&", "$(", "`", "|", "${"]):
                            raise SecurityError("illegal char")

                if shutil.which("firejail"):
                    if isinstance(command, list):
                        # 🔥 NAMESPACE COMPARTILHADO FIXO
                        
                        is_first = len(self._processes) == 0

                        if self._env.ip:
                            if is_first:
                                # Primeiro processo: cria namespace
                                firejail_cmd = [
                                    firejail_path,
                                    "--chroot=" + real_cwd,
                                    "--net=namespace",
                                    f"--ip={self._env.ip}",
                                    f"--defaultgw={self._env.ip.rsplit('.', 1)[0]}.1",
                                    "--dns=8.8.8.8",
                                    "--dns=8.8.4.4",
                                    "--noroot",
                                    "--private-pid",  # CRIA
                                    f"--name={namespace_name}",  # NOME FIXO
                                    "--private-ipc",
                                    "--private-uts",
                                    "--private",
                                    "--private-dev",
                                    "--private-proc",
                                    "--private-sys",
                                    "--ignore=env",
                                    "--ignore=shell", 
                                    "--private-tmp",
                                    "--private-run",       
                                    "--private-etc",
                                    "--seccomp",
                                    "--caps.drop=all",
                                ] + command
                            else:
                                # Processos seguintes: junta
                                firejail_cmd = [
                                    firejail_path,
                                    f"--join={namespace_name}"
                                ] + command
                        else:
                            # Sem IP
                            if is_first:
                                firejail_cmd = [
                                    firejail_path,
                                    "--chroot=" + real_cwd,
                                    "--net=none",
                                    "--noroot",
                                    "--private-pid",  # CRIA
                                    f"--name={namespace_name}",  # NOME FIXO
                                    "--private-ipc",
                                    "--private-uts",
                                    "--private",
                                    "--private-dev",
                                    "--private-proc",
                                    "--private-sys",
                                    "--ignore=env",
                                    "--ignore=shell",
                                    "--private-tmp",
                                    "--private-run",
                                    "--private-etc",
                                    "--seccomp",
                                    "--caps.drop=all",
                                ] + command
                            else:
                                firejail_cmd = [
                                    firejail_path,
                                    f"--join={namespace_name}"
                                ] + command

                        com = firejail_cmd
                    else:
                        # Para command como string (comando shell)
                        if shell:
                            # Se shell=True, executa o comando string diretamente
                            if self._env.ip:
                                if is_first:
                                    firejail_cmd = f"{firejail_path} --chroot={real_cwd} --net=namespace --ip={self._env.ip} --defaultgw={self._env.ip.rsplit('.', 1)[0]}.1 --dns=8.8.8.8 --dns=8.8.4.4 --noroot --private-pid --name={namespace_name} --private-ipc --private-uts --private --private-dev --private-proc --private-sys --ignore=env --ignore=shell --private-tmp --private-run --private-etc --seccomp --caps.drop=all {command}"
                                else:
                                    firejail_cmd = f"{firejail_path} --join={namespace_name} {command}"
                            else:
                                if is_first:
                                    firejail_cmd = f"{firejail_path} --chroot={real_cwd} --net=none --noroot --private-pid --name={namespace_name} --private-ipc --private-uts --private --private-dev --private-proc --private-sys --ignore=env --ignore=shell --private-tmp --private-run --private-etc --seccomp --caps.drop=all {command}"
                                else:
                                    firejail_cmd = f"{firejail_path} --join={namespace_name} {command}"
                            com = firejail_cmd
                            shell = True  # Mantém shell=True para execução
                else:
                    com = command

                kwargs = {"cwd": real_cwd} if not shutil.which("firejail") else {}
                kwargs.update({
                    "env": process_env,
                    "stdin": stdin,
                    "stdout": stdout,
                    "stderr": stderr,
                    "shell": shell
                })

                proc = subprocess.Popen(com, **kwargs)

                with self._lock:
                    pid = self._next_pid
                    self._next_pid += 1
                    self._processes[pid] = proc

                return proc

            except Exception as e:
                raise RuntimeError(f"Failed to run command: {e}")






        def _create_preexec_fn(self, env_vars):
            """Create pre-execution function for process isolation"""
            def preexec():
                # Drop privileges
                os.setgroups([])
                os.setgid(1000)
                os.setuid(1000)
                
                
                # Apply virtual environment variables
                for key, value in env_vars.items():
                    os.putenv(key, value)  # Define para processo filho
                    os.environ[key] = value  # Define para processo atual
        
                #Remove variáveis que não estão no ambiente virtual
                for key in list(os.environ.keys()):
                     if key not in env_vars:
                         os.unsetenv(key)
                         if key in os.environ:
                             del os.environ[key]
            return preexec
        
        def kill(self, pid: int, Signal: int = signal.SIGTERM):
            """Kill a process"""
            with self._lock:
                if pid in self._processes:
                    proc = self._processes[pid]
                    try:
                        proc.send_signal(Signal)
                    except:
                        pass
                else:
                    # Try to kill system process (if we have permission)
                    try:
                        os.kill(pid, getattr(signal, Signal))
                    except ProcessLookupError:
                        raise ValueError(f"Process {pid} not found")
        
        def terminate(self, pid: int):
            """Terminate a process gracefully"""
            self.kill(pid, signal.SIGTERM)
        
        def killall(self):
            """Kill all processes in this environment"""
            with self._lock:
                for pid, proc in list(self._processes.items()):
                    try:
                        proc.terminate()
                    except:
                        pass
                
                # Wait for processes to terminate
                for pid, proc in list(self._processes.items()):
                    try:
                        proc.wait(timeout=5)
                    except:
                        try:
                            proc.kill()
                        except:
                            pass
                
                self._processes.clear()
        
        def list(self) -> List[Dict[str, Any]]:
            """List all processes in the environment"""
            result = []
            with self._lock:
                for pid, proc in self._processes.items():
                    result.append({
                        'pid': pid,
                        'command': ' '.join(proc.args) if isinstance(proc.args, list) else proc.args,
                        'status': proc.poll()
                    })
            return result
        
        def wait(self, pid: int, timeout: Optional[float] = None) -> Optional[int]:
            """Wait for a process to complete"""
            with self._lock:
                if pid in self._processes:
                    try:
                        return self._processes[pid].wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        return None
                else:
                    # Try to wait for system process
                    try:
                        os.waitpid(pid, 0)
                        return 0
                    except ChildProcessError:
                        return None
        
        def get_returncode(self, pid: int) -> Optional[int]:
            """Get process return code"""
            with self._lock:
                if pid in self._processes:
                    return self._processes[pid].returncode
            return None
        
        def communicate(self, pid: int, input_data: Optional[bytes] = None, 
                       timeout: Optional[float] = None) -> Tuple[bytes, bytes]:
            """Communicate with a process"""
            with self._lock:
                if pid in self._processes:
                    return self._processes[pid].communicate(input=input_data, timeout=timeout)
                else:
                    raise ValueError(f"Process {pid} not found")
    
    class Package:
        """Package and module manager"""
        
        def __init__(self, environ_instance: 'VirtualEnviron'):
            self._env = environ_instance
            self._modules = {}
            self._setup_python_path()
        
        def _setup_python_path(self):
            """Setup Python module search path for the environment"""
            try:
                versao = ".".join(sys.version.split(".")[:2])
                shutil.copytree(f"/lib/python{versao}", self._env.fs._to_virtual_path(f"/lib/python{versao}"), ignore=lambda d, files: ["site-packages"])
                os.makedirs(os.path.join(self._env._base_path, "lib", f"python{versao}", "site-packages"), exist_ok=True)
            except FileNotFoundError:
                 try:
                     versao = ".".join(sys.version.split(".")[:2])
                     shutil.copytree(f"/usr/lib/python{versao}", self._env.fs._to_virtual_path(f"/lib/python{versao}"), ignore=lambda d, files: ["site-packages"])
                     os.makedirs(os.path.join(self._env._base_path, "lib", f"python{versao}", "site-packages"), exist_ok=True)
                 except:
                     os.makedirs(os.path.join(self._env._base_path, "lib", f"python{versao}"), exist_ok=True)
                 
            python_lib = os.path.join(self._env._base_path, 'lib', f'python{versao}')
                        
            # Add to sys.path for processes in this environment
            self._env.environ.set('PYTHONPATH', python_lib)
        
        def import_module(self, module_name: str, from_env: str = 'virtual'):
            """Import a module from specified environment"""
            if from_env == 'real-os':
                # Import from real system
                return importlib.import_module(module_name)
            elif from_env == 'virtual':
                # Import from virtual environment
                return self._import_virtual_module(module_name)
            elif from_env in self._env._other_environments:
                # Import from another virtual environment
                other_env = self._env._other_environments[from_env]
                return other_env.package._import_virtual_module(module_name)
            else:
                raise ValueError(f"Unknown environment: {from_env}")
        
        def _import_virtual_module(self, module_name: str):
            """Import module from virtual environment"""
            # First check if module is already loaded
            if module_name in self._modules:
                return self._modules[module_name]
            
            # Try to import from virtual Python path
            python_lib = os.path.join(self._env._base_path, 'lib', 'python3')
            
            # Convert module name to file path
            module_path = module_name.replace('.', '/')
            
            # Try .py file
            py_file = os.path.join(python_lib, f"{module_path}.py")
            if os.path.exists(py_file):
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self._modules[module_name] = module
                return module
            
            # Try package
            package_dir = os.path.join(python_lib, module_path)
            init_file = os.path.join(package_dir, '__init__.py')
            if os.path.exists(init_file):
                spec = importlib.util.spec_from_file_location(module_name, init_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self._modules[module_name] = module
                return module
            
            # If not found in virtual environment, try to import from system
            # but in a sandboxed way
            try:
                module = importlib.import_module(module_name)
                
                # Create a wrapper to intercept file operations
                wrapped_module = self._wrap_module(module)
                self._modules[module_name] = wrapped_module
                return wrapped_module
            except ImportError:
                raise ImportError(f"No module named '{module_name}' in virtual environment")
        
        def _wrap_module(self, module):
            """Wrap a module to intercept file operations"""
            # This is a simplified wrapper
            # In a real implementation, you would need to wrap many operations
            return module
        
        def install(self, package_name: str, source: str = 'pypi'):
            """Install a package in the virtual environment"""
            python_bin = os.path.join(self._env._base_path, 'bin', 'python')
            
            if source == 'pypi':
                # Use pip to install from PyPI
                cmd = [python_bin, '-m', 'pip', 'install', '--prefix', self._env._base_path, package_name]
            elif source.startswith('http://') or source.startswith('https://'):
                # Install from URL
                cmd = [python_bin, '-m', 'pip', 'install', '--prefix', self._env._base_path, source]
            elif os.path.exists(source):
                # Install from local file/directory
                cmd = [python_bin, '-m', 'pip', 'install', '--prefix', self._env._base_path, source]
            else:
                raise ValueError(f"Unknown package source: {source}")
            
            # Run installation
            result = self._env.process.run(cmd, capture_output=True)
            return result.returncode == 0
        
        def uninstall(self, package_name: str):
            """Uninstall a package from the virtual environment"""
            python_bin = os.path.join(self._env._base_path, 'bin', 'python')
            cmd = [python_bin, '-m', 'pip', 'uninstall', '--yes', '--prefix', self._env._base_path, package_name]
            
            result = self._env.process.run(cmd, capture_output=True)
            return result.returncode == 0
        
        def list_installed(self) -> List[str]:
            """List installed packages"""
            python_bin = os.path.join(self._env._base_path, 'bin', 'python')
            cmd = [python_bin, '-m', 'pip', 'list', '--format=freeze', '--prefix', self._env._base_path]
            
            result = self._env.process.run(cmd, capture_output=True)
            if result.returncode == 0:
                packages = []
                for line in result.stdout.decode().split('\n'):
                    if line.strip():
                        packages.append(line.split('==')[0])
                return packages
            return []
        
        def create_module(self, module_name: str, code: str):
            """Create a Python module in the virtual environment"""
            # Convert module name to file path
            module_path = module_name.replace('.', '/')
            py_file = os.path.join(self._env._base_path, 'lib', 'python', f"{module_path}.py")
            
            # Create directory if needed
            os.makedirs(os.path.dirname(py_file), exist_ok=True)
            
            # Write module code
            with open(py_file, 'w') as f:
                f.write(code)
            
            # Clear module cache
            if module_name in self._modules:
                del self._modules[module_name]
        
        def copy(self, lib):
            a = __import__(lib)
            b = inspect.getsource(a)
            return self.create_module(lib, b)
    class Library:
        def __init__(self, env):
            self._env = env
        def set_path(self, paths):
            self._env.environ.set("LD_LIBRARY_PATH", paths)
        def set_preload(self, path):
            self._env.environ.set("LD_PRELOAD", path)
            if self._env.fs.exists("/lib/libsandbox.so"):
                self._env.virtpyLib.set_libsandbox()
        def unset_preload(self):
            self._env.environ.unset("LD_PRELOAD")
        def get_path(self):
            return self._env.environ.get("LD_LIBRARY_PATH", "?")
        def create_lib(self, name, source):
            path = self._env.environ.get("LD_LIBRARY_PATH").split(":")[0]
            output_file = f"{path}/{name}.so"
    
            try:
                # Compilar passando source via stdin
                result = subprocess.run(
                    ['gcc', '-shared', '-fPIC', '-o', output_file, '-x', 'c', '-'],
                    input=source,
                    capture_output=True,
                    text=True
        )
        
                if result.returncode != 0:
                    error_msg = result.stderr.strip() if result.stderr else "Erro desconhecido na compilação"
                    return (False, None, error_msg)
        
                return (True, output_file, "Biblioteca criada com sucesso")
        
            except FileNotFoundError:
                return (False, None, "Comando gcc não encontrado. Instale o compilador C.")
            except PermissionError:
                return (False, None, f"Permissão negada para criar arquivo em {output_file}")
            except Exception as e:
                return (False, None, f"Erro inesperado: {str(e)}")
        def copy(self, lib):
            for path in os.environ.get("LD_LIBRARY_PATH", "/lib").split(":"):
                full = glob.glob(f"{path}/lib{lib}.so*")
                if full: return shutil.copy(full[0], os.path.join(
                self._env._base_path, 
                self._env.environ.get("LD_LIBRARY_PATH").split(":")[0],
                os.path.basename(full[0])
            ))
        def add_path(self, path):
            atual = self._env.environ.get("LD_LIBRARY_PATH")
            self._env.environ.set("LD_LIBRARY_PATH", atual + ":" + path)
     



    # Main VirtualEnviron class implementation
    def __init__(self, nome: str, vars: Optional[Dict[str, str]] = None, ip: Optional[str] = None, create_opt: bool = False, install_pkm: bool = False):
        """
        Initialize a new virtual environment.
        
        Args:
            nome: Name of the environment
            vars: Environment variables to set
            ip: IP address for the environment (for network isolation)
            start: Commands to run when starting the environment
            setup: Commands to run during setup
        """
        self.create_opt = create_opt
        self.install_pkm = install_pkm
        self.ip = ip
        self.name = nome
        self.vars = vars or {}
        self.ready = False
        
        
        # Internal state
        self._base_path = os.path.join(tempfile.gettempdir(), f'virtpy_{self.name}_{uuid.uuid4().hex[:8]}')
       
        
        self._running = False
        self._pid = None
        self._lock = threading.Lock()
        self._other_environments = {}
        
        # Initialize sub-managers
        
        self.environ = self.Environ(self)
        if vars:
            self.environ.update(vars)
        
        self.fs = self.Fs(self)
        
        self.process = self.Process(self)
        self.package = self.Package(self)
        self.library = self.Library(self)
        self.virtpyLib = self.virtpy_lib(self)
        self.internal_api = VirtPyInternalAPI(self)  # Adicionar esta linha
        # Run setup commands
        if not self.ready:
            self.setup()

    def start(self):
        """Start the virtual environment"""
        with self._lock:
            if self._running:
                return
            
            # Create the environment directory if it doesn't exist
           
            os.makedirs(self._base_path, exist_ok=True)
            
            # Setup network namespace if IP is provided
            if self.ip and PYROUTE2_AVAILABLE:
                self._setup_network()
            
            
            self.internal_api.expose_to_environment()  # Expõe a API
            self.internal_api.start_api_server()       # Inicia servidor
            
            
            
            self._running = True
            
            # Register cleanup
            atexit.register(self.shutdown)
            
    
    def shutdown(self, root_backup=True):
        """Shutdown the virtual environment"""
        with self._lock:
            if not self._running:
                return
            
            
            self.internal_api.stop_api_server()  # Adicionar esta linha
            # Kill all processes
            
            self.process.killall()
            
            # Cleanup network
            if self.ip and PYROUTE2_AVAILABLE:
                self._cleanup_network()
            
            # Remove temporary directory
            try:
               
                if not root_backup: shutil.rmtree(self._base_path, ignore_errors=True)
            except:
                pass
            
            self._running = False
    
    def restart(self):
        """Restart the virtual environment"""
        
        self.shutdown()
        time.sleep(1)  # Brief pause
        self.start()
    
    def setup(self):
        """Run setup commands"""
        
        # setup essential libraries
        c = self.library.copy("c") # essencial
        m = self.library.copy("m") # para matematica
        pth = self.library.copy("pthread") # para threads
        if not c:
            self.virtpyLib.create_libc_mini()
        if not m:
            self.virtpyLib.create_libm_mini()
        if not pth:
            self.virtpyLib.create_libpth_mini()
        self.library.copy("dl") # sei la
        self.library.copy("rt") # para tempo real
        self.library.copy("util") # utilidades
        self.library.copy("z") # zip
        self.library.copy("ssl") # ssl
        self.library.copy("sqlite3") # sqlite3
        self.library.copy("crypto") # sei la
        self.library.copy("uuid") # biblioteca uuid
        self.library.copy("readline") # sei la
        self.library.copy("crypt")      # libcrypt.so - Criptografia Unix (pwd, spwd)
        self.library.copy("nsl")        # libnsl.so - Network services (antigo, ainda usado)
        self.library.copy("resolv")     # libresolv.so - Resolução DNS
        self.library.copy("gdbm")       # libgdbm.so - Banco de dados GNU (dbm.gnu)
        self.library.copy("db")         # libdb.so - Berkeley DB (bsddb)
        self.library.copy("bz2")        # libbz2.so - Compactação bzip2
        self.library.copy("lzma")       # liblzma.so - Compactação LZMA
        python_bin = os.path.join(self._base_path, "bin", "python3")
        if os.path.exists(python_bin):
            try:
                # Executa o python com --version para forçar carregamento de libs
                result = subprocess.run(
                    ["ldd", python_bin],
                    capture_output=True,
                    text=True
                )
                
                # Analisa o output do ldd para encontrar libs "not found"
                for line in result.stdout.split('\n'):
                    if 'not found' in line:
                        # Extrai o nome da lib (ex: libpython3.13.so)
                        match = re.search(r'(lib[^\.]+\.so[^ ]*)', line)
                        if match:
                            lib_full = match.group(1)
                            # Remove 'lib' no início e '.so' no final
                            lib_base = lib_full.replace('lib', '', 1).split('.so')[0]
                            print(f"Faltando: {lib_base}")
                            self.library.copy(lib_base)
            except Exception as e:
                print(f"Erro ao verificar libs: {e}")
                # Copia apenas as mais críticas
                self.library.copy("python*")
                self.library.copy("c++") # pode precisar em pydroid
                self.library.copy("log")
                self.library.copy("backcompat_shared")
            self.library.copy("python*")
            self.library.copy("c++") # pode precisar em pydroid
            self.library.copy("log")
            self.library.copy("backcompat_shared")
            if not shutil.which("firejail"):
                r = self.virtpyLib.create_sandbox_preload(os.getpid(), self._base_path)
                if r["sucess"]:
                    self.virtpyLib.set_libsandbox()
    
    
    
    # Na classe VirtualEnviron, atualize o método _setup_network:
    def _setup_network(self):
        """Setup real network namespace with virtual IP address"""
        # Verifica se estamos no Linux
        if sys.platform != 'linux':
            print(f"Network namespaces only supported on Linux. Current: {sys.platform}")
            return

        # Verifica se temos privilégios de root
        if os.geteuid() != 0:
            print("Root privileges required for network namespace setup.")
            print("Please run with sudo or as root.")
            return

        try:
            # Nome do namespace baseado no nome do ambiente
            ns_name = f"virtpy_{self.name}"
            self._network_namespace = ns_name

            # Cria namespace de rede
            self._create_network_namespace(ns_name)

            # Cria par de interfaces virtuais
            veth_host, veth_ns = self._create_veth_pair(ns_name)

            # Configura IP no namespace
            self._configure_namespace_ip(ns_name, veth_ns)

            # Configura roteamento
            self._setup_routing(ns_name, veth_host)

            # Configura DNS no namespace
            self._setup_namespace_dns(ns_name)

            print(f"✓ Network namespace '{ns_name}' created with IP: {self.ip}")

        except Exception as e:
            print(f"✗ Network setup failed: {e}")
            # Limpa recursos em caso de erro
            self._cleanup_network()

    def _create_network_namespace(self, ns_name: str):
        """Create a network namespace"""
        try:
            # Cria namespace
            subprocess.run(['ip', 'netns', 'add', ns_name],
                          check=True, capture_output=True)

            # Ativa loopback dentro do namespace
            subprocess.run(['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'lo', 'up'],
                          check=True, capture_output=True)

            # Salva informações do namespace
            self._network_namespace = ns_name

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create network namespace: {e.stderr.decode()}")

    def _create_veth_pair(self, ns_name: str) -> Tuple[str, str]:
        """Create virtual ethernet pair connecting host to namespace"""
        # Nomes das interfaces
        veth_host = f"veth_{ns_name}_host"
        veth_ns = f"veth_{ns_name}_ns"

        try:
            # Cria par de interfaces veth
            subprocess.run(['ip', 'link', 'add', veth_host, 'type', 'veth', 'peer', 'name', veth_ns],
                          check=True, capture_output=True)

            # Move uma interface para o namespace
            subprocess.run(['ip', 'link', 'set', veth_ns, 'netns', ns_name],
                          check=True, capture_output=True)

            # Ativa a interface no host
            subprocess.run(['ip', 'link', 'set', veth_host, 'up'],
                          check=True, capture_output=True)

            # Ativa a interface no namespace
            subprocess.run(['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', veth_ns, 'up'],
                          check=True, capture_output=True)

            return veth_host, veth_ns

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create veth pair: {e.stderr.decode()}")

    def _configure_namespace_ip(self, ns_name: str, veth_ns: str):
        """Configure IP address inside the namespace"""
        if not self.ip:
            # Usa IP padrão se não fornecido
            self.ip = "10.100.0.2"

        try:
            # Define IP no namespace
            subprocess.run(['ip', 'netns', 'exec', ns_name, 'ip', 'addr', 'add',
                           f'{self.ip}/24', 'dev', veth_ns],
                          check=True, capture_output=True)

            # Configura rota padrão
            gateway = self.ip.rsplit('.', 1)[0] + '.1'
            subprocess.run(['ip', 'netns', 'exec', ns_name, 'ip', 'route', 'add',
                           'default', 'via', gateway],
                          check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to configure IP: {e.stderr.decode()}")

    def _setup_routing(self, ns_name: str, veth_host: str):
        """Setup routing between host and namespace"""
        try:
            # Configura IP na interface do host
            gateway_ip = self.ip.rsplit('.', 1)[0] + '.1'
            subprocess.run(['ip', 'addr', 'add', f'{gateway_ip}/24', 'dev', veth_host],
                          check=True, capture_output=True)

            # Habilita forwarding no host
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                          check=True, capture_output=True)

            # Configura NAT para acesso à internet (opcional)
            self._setup_nat(namespace_ip=f"{self.ip}/24")

            print(f"✓ Routing configured: {gateway_ip} -> {self.ip}")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to setup routing: {e.stderr.decode()}")

    def _setup_nat(self, namespace_ip: str):
        """Setup NAT for internet access from namespace"""
        try:
            # Identifica interface de internet principal
            default_iface_cmd = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True
            )

            if default_iface_cmd.returncode == 0:
                default_line = default_iface_cmd.stdout.strip().split('')[0]
                iface = default_line.split('dev ')[1].split(' ')[0]

                # Configura iptables para NAT
                subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                              '-s', namespace_ip, '-o', iface, '-j', 'MASQUERADE'],
                              check=True)

                # Permite forwarding
                subprocess.run(['iptables', '-A', 'FORWARD',
                              '-i', iface, '-o', iface, '-j', 'ACCEPT'],
                              check=True)
                subprocess.run(['iptables', '-A', 'FORWARD',
                              '-i', iface, '-o', iface, '-m', 'state',
                              '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                              check=True)

                print(f"✓ NAT configured for interface: {iface}")

        except subprocess.CalledProcessError as e:
            print(f"Warning: NAT setup failed: {e}")

    def _setup_namespace_dns(self, ns_name: str):
        """Setup DNS configuration inside namespace"""
        try:
            # Cria arquivo resolv.conf no namespace
            resolv_content = """nameserver 8.8.8.8
    nameserver 8.8.4.4
    nameserver 1.1.1.1
    """

            # Cria diretório para mount bind
            netns_dir = f"/etc/netns/{ns_name}"
            os.makedirs(netns_dir, exist_ok=True)

            # Cria resolv.conf específico para o namespace
            resolv_path = f"{netns_dir}/resolv.conf"
            with open(resolv_path, 'w') as f:
                f.write(resolv_content)

            # Monta o arquivo no namespace usando mount namespace
            self._mount_resolv_to_namespace(ns_name, resolv_path)

        except Exception as e:
            print(f"Warning: DNS setup failed: {e}")

    def _mount_resolv_to_namespace(self, ns_name: str, resolv_path: str):
        """Mount resolv.conf to namespace using mount namespace"""
        # Cria um mount namespace temporário para copiar o resolv.conf
        mount_script = textwrap.dedent(f"""
        #!/bin/bash
        # Cria diretório /etc no namespace se não existir
        ip netns exec {ns_name} mkdir -p /etc 2>/dev/null
        # Monta o resolv.conf
        mount --bind {resolv_path} /etc/netns/{ns_name}/resolv.conf 2>/dev/null
        """)

        script_path = "/tmp/setup_resolv.sh"
        with open(script_path, 'w') as f:
            f.write(mount_script)

        os.chmod(script_path, 0o755)

        try:
            subprocess.run([script_path], check=True)
        except:
            # Fallback: copia o arquivo diretamente
            self._copy_resolv_to_namespace(ns_name, resolv_path)

    def _copy_resolv_to_namespace(self, ns_name: str, resolv_path: str):
        """Copy resolv.conf to namespace (fallback method)"""
        try:
            # Usa nsenter para entrar no mount namespace
            with open(resolv_path, 'r') as f:
                resolv_content = f.read()

            # Cria arquivo resolv.conf usando ip netns exec
            subprocess.run(['ip', 'netns', 'exec', ns_name, 'mkdir', '-p', '/etc'],
                          check=True, capture_output=True)

            temp_file = f"/tmp/resolv_{ns_name}.conf"
            with open(temp_file, 'w') as f:
                f.write(resolv_content)

            subprocess.run(['ip', 'netns', 'exec', ns_name, 'cp', temp_file, '/etc/resolv.conf'],
                          check=True, capture_output=True)

            os.unlink(temp_file)

        except Exception as e:
            print(f"DNS copy fallback failed: {e}")

    # Atualize também o método _cleanup_network:
    def _cleanup_network(self):
        """Cleanup all network resources"""
        if not hasattr(self, '_network_namespace') or not self._network_namespace:
            return

        ns_name = self._network_namespace

        try:
            # Remove NAT rules
            if hasattr(self, 'ip') and self.ip:
                namespace_ip = f"{self.ip}/24"
                try:
                    subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING',
                                  '-s', namespace_ip, '-j', 'MASQUERADE'],
                                 capture_output=True)
                except:
                    pass

            # Remove namespace (isso também remove todas as interfaces dentro dele)
            subprocess.run(['ip', 'netns', 'delete', ns_name],
                          capture_output=True)

            # Remove diretório de configuração do namespace
            netns_dir = f"/etc/netns/{ns_name}"
            if os.path.exists(netns_dir):
                shutil.rmtree(netns_dir, ignore_errors=True)

            print(f"✓ Network namespace '{ns_name}' cleaned up")

        except Exception as e:
            print(f"Warning: Network cleanup failed: {e}")
        finally:
            self._network_namespace = None

    # Adicione um método para executar comandos no namespace:
    def run_in_namespace(self, command: Union[str, List[str]],
                         capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a command inside the network namespace"""
        if not hasattr(self, '_network_namespace') or not self._network_namespace:
            # Executa normalmente se não houver namespace
            return self.process.run(command, capture_output=capture_output)

        ns_name = self._network_namespace

        # Prepara comando para execução no namespace
        if isinstance(command, str):
            cmd_list = ['ip', 'netns', 'exec', ns_name] + command.split()
        else:
            cmd_list = ['ip', 'netns', 'exec', ns_name] + command

        try:
            result = subprocess.run(cmd_list,
                                  capture_output=capture_output,
                                  text=not capture_output)
            return result
        except Exception as e:
            raise RuntimeError(f"Failed to run in namespace: {e}")

    # Adicione um método para verificar conectividade:
    def test_network_connectivity(self, target: str = "8.8.8.8") -> bool:
        """Test network connectivity from the namespace"""
        if not hasattr(self, '_network_namespace') or not self._network_namespace:
            return False

        try:
            result = self.run_in_namespace(['ping', '-c', '2', '-W', '2', target],
                                          capture_output=True)
            return result.returncode == 0
        except:
            return False




    
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        
        self.shutdown()
    
        # Não suprime exceções
        return False
    
    def __del__(self):
        """Destructor"""
        try:
            if self._running:
                self.shutdown()
        except:
            pass
    def reinstall(self):
        self.shutdown()
        self.environ.clear()
        lista = [p.split("==")[0] for p in self.package.list_installed()]
        for p in lista:
            self.package.uninstall(p)
        for f in self.fs.listdir("/"):
            self.fs.remove(f"/{f}")
        # recria lib e bin
        self.fs._setup_fs()
        
        self.ready = False
        time.sleep(1)





__all__ = ["VirtualEnviron"]