"""
Core implementation of VirtPy - Complete Virtual Environments
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
    
    class Fs:
        """Virtual Filesystem manager"""
        
        def __init__(self, environ_instance: 'VirtualEnviron'):
            self._env = environ_instance
            self._base_path = environ_instance._base_path
            self._setup_fs()
        
        def _setup_fs(self):
            """Initialize virtual filesystem structure"""
            os.makedirs(self._base_path, exist_ok=True)
            dirs = ["bin"] 
            for d in dirs:
                os.makedirs(os.path.join(self._base_path, d), exist_ok=True)
            
            
            
            # Install basic Python in the environment
            self._install_python()
        
        def _create_etc_files(self):
            """Create essential /etc files"""
            etc_path = os.path.join(self._base_path, 'etc')
            
            # hostname
            with open(os.path.join(etc_path, 'hostname'), 'w') as f:
                f.write(self._env.name + '\n')
            
            # hosts
            with open(os.path.join(etc_path, 'hosts'), 'w') as f:
                f.write("127.0.0.1\tlocalhost\n")
                if self._env.ip:
                    f.write(f"{self._env.ip}\t{self._env.name}\n")
            
            # passwd
            with open(os.path.join(etc_path, 'passwd'), 'w') as f:
                f.write("root:x:0:0:root:/root:/bin/bash\n")
                f.write(f"{self._env.name}:x:1000:1000:{self._env.name}:/home/{self._env.name}:/bin/bash\n")
        
        def _install_python(self):
            """Install Python interpreter in the environment"""
            # Create symbolic links to system Python (or copy if needed)
            bin_path = os.path.join(self._base_path, 'bin')
            python_path = shutil.which('python3') or shutil.which('python')
            
            if python_path:
                target_path = os.path.join(bin_path, 'python3')
                if not os.path.exists(target_path):
                    os.symlink(python_path, target_path)
                os.symlink(target_path, os.path.join(bin_path, 'python'))
        
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
                if e.errno == errno.ELOOP:  # É symlink!
                    raise SecurityError(f"Symlink not allowed: {path}")
        
    
            # Ensure we don't escape the base directory
            if not os.path.commonpath([base, os.path.abspath(full_path)]) == base:
                raise SecurityError(f"Attempted directory traversal: {path}")
    
            return full_path
        
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
                'PATH': '/bin',
                'USER': self._env.name,
                'LOGNAME': self._env.name,
                'SHELL': '/bin/bash',
                'PWD': '/',
                'VIRTPY_ENV': self._env.name,
                'VIRTPY_BASE': self._env._base_path,
            })
            
            # Add Python-specific variables
            python_path = os.path.join(self._env._base_path, 'lib', 'python')
            self._vars['PYTHONPATH'] = python_path
            self._vars['PYTHONHOME'] = os.path.join(self._env._base_path, 'usr')
        
        def get(self, key: str, default: Any = None) -> Any:
            """Get environment variable"""
            return self._vars.get(key, default)
        
        def set(self, key: str, value: Any):
            """Set environment variable"""
            self._vars[key] = str(value)
        
        def unset(self, key: str):
            """Unset environment variable"""
            if key in self._vars:
                del self._vars[key]
        
        def update(self, vars_dict: Dict[str, Any]):
            """Update multiple environment variables"""
            self._vars.update({k: str(v) for k, v in vars_dict.items()})
        
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
            self._vars = vars
        
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
            '''Run a command in the virtual environment'''

            # Prepare environment
            process_env = self._env.environ.to_dict()
            process_env.update(self._env.environ.to_dict())
            if env:
                process_env.update(env)

            # ========== NOVA LÓGICA: VERIFICA USE_DEFAULT_COMMAND ==========
            use_default_command = process_env.get('USE_DEFAULT_COMMAND', 'true').lower() == 'true'

            # Prepare command
            if isinstance(command, str) and not shell:
                command_parts = command.split()
            elif isinstance(command, list):
                command_parts = command.copy()
            else:
                command_parts = [command]

            # Se USE_DEFAULT_COMMAND é false, procura comando no PATH
            if not use_default_command and command_parts:
                first_cmd = command_parts[0]
                # Não procura comandos built-in do shell ou caminhos absolutos
                if not first_cmd.startswith(('/', '.', '~')) and '/' not in first_cmd:
                    found_cmd = self._find_command_in_path(first_cmd, process_env)

                    if found_cmd:
                        # Substitui o comando pelo caminho encontrado
                        command_parts[0] = found_cmd

                        # Se for um script Python, adiciona python antes
                        if found_cmd.endswith('.py'):
                            command_parts = ['python'] + command_parts
                    else:
                        # Comando não encontrado no PATH
                        raise RuntimeError(f"Command '{first_cmd}' not found in PATH")

            # Agora command_parts contém o comando correto
            command = command_parts
            # ========== FIM DA NOVA LÓGICA ==========

            # Prepare working directory
            if cwd:
                real_cwd = self._env.fs._to_virtual_path(cwd)
            else:
                real_cwd = self._env._base_path

            # Create pipes for redirection if needed
            stdin = subprocess.PIPE if input_data is not None else None
            stdout = subprocess.PIPE if capture_output else None
            stderr = subprocess.PIPE if capture_output else subprocess.STDOUT

            try:
                # Run with chroot isolation
                if hasattr(os, 'chroot'):
                    # Save current root
                    original_root = os.open('/', os.O_RDONLY)

                    try:
                        # Chroot to virtual environment
                        os.chroot(self._env._base_path)
                        os.chdir('/')

                        # Run the process
                        proc = subprocess.Popen(
                            command,  # Usa command que pode ter sido modificado
                            cwd=real_cwd[len(self._env._base_path):] if real_cwd.startswith(self._env._base_path) else '/',
                            env=process_env,                            stdin=stdin,
                            stdout=stdout,
                            stderr=stderr,
                            shell=shell,
                            preexec_fn=self._create_preexec_fn(process_env)
                        )
                    finally:
                        # Restore original root
                        os.fchdir(original_root)
                        os.chroot('.')
                        os.close(original_root)
                else:
                    # Fallback without chroot
                    proc = subprocess.Popen(                        command,  # Usa command que pode ter sido modificado
                        cwd=real_cwd,
                        env=process_env,
                        stdin=stdin,
                        stdout=stdout,
                        stderr=stderr,
                        shell=shell
                    )

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
        
        def kill(self, pid: int, signal: int = signal.SIGTERM):
            """Kill a process"""
            with self._lock:
                if pid in self._processes:
                    proc = self._processes[pid]
                    try:
                        proc.send_signal(signal)
                    except:
                        pass
                else:
                    # Try to kill system process (if we have permission)
                    try:
                        os.kill(pid, signal)
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
            # Create Python lib directory
            python_lib = os.path.join(self._env._base_path, 'lib', 'python')
            os.makedirs(python_lib, exist_ok=True)
            
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
            python_lib = os.path.join(self._env._base_path, 'lib', 'python')
            
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
        
        def include(self, lib):
            a = __import__(lib)
            b = inspect.getsource(a)
            return self.create_module(lib, b)
    
    # Main VirtualEnviron class implementation
    def __init__(self, nome: str, vars: Optional[Dict[str, str]] = None, start: Optional[List[str]] = None,
                 setup: Optional[List[str]] = None, ip: Optional[str] = None):
        """
        Initialize a new virtual environment.
        
        Args:
            nome: Name of the environment
            vars: Environment variables to set
            ip: IP address for the environment (for network isolation)
            start: Commands to run when starting the environment
            setup: Commands to run during setup
        """
        self.ip = ip
        self.name = nome
        self.vars = vars or {}
        self.start_commands = start or []
        self.setup_commands = setup or []
        
        # Internal state
        self._base_path = os.path.join(tempfile.gettempdir(), f'virtpy_{self.name}_{uuid.uuid4().hex[:8]}')
        
        self._running = False
        self._pid = None
        self._lock = threading.Lock()
        self._other_environments = {}
        
        # Initialize sub-managers
        self.fs = self.Fs(self)
        self.environ = self.Environ(self)
        self.process = self.Process(self)
        self.package = self.Package(self)
        self.internal_api = VirtPyInternalAPI(self)  # Adicionar esta linha
        # Run setup commands
        if self.setup_commands:
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
            
            # Run start commands
            for cmd in self.start_commands:
                self.process.run(cmd, shell=True)
            
            self._running = True
            
            # Register cleanup
            atexit.register(self.shutdown)
    
    def shutdown(self):
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
                shutil.rmtree(self._base_path, ignore_errors=True)
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
        for cmd in self.setup_commands:
            result = self.process.run(cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                print(f"Setup command failed: {cmd}")
                print(f"Error: {result.stderr.decode() if result.stderr else 'Unknown error'}")
    
    def getpid(self) -> Optional[int]:
        """Get the main process ID if environment runs as separate process"""
        return self._pid
    
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

__all__ = ["VirtualEnviron"]
