# VirtPy - Complete Virtual Environments for Python

VirtPy is a powerful Python library for creating isolated virtual environments with process, filesystem, and network isolation.

## Features

- 🚀 **Process Isolation**: Run commands in isolated environments
- 📁 **Virtual Filesystem**: Complete filesystem sandboxing
- 🌐 **Network Namespaces**: Isolated network stacks (Linux only)
- 🔌 **Inter-Process Communication**: Rich API for process communication
- 🔒 **Security**: Directory traversal prevention, symlink protection
- 🐍 **Python Native**: 100% Python, no external dependencies required

## Quick Start

```bash
# Install
pip install git+https://github.com/seuusuario/virtpy.git

# Install with optional dependencies
pip install "virtpy[full]"
```

```python
from virtpy import VirtualEnviron

# Create a virtual environment
env = VirtualEnviron(
    name="myapp",
    vars={"DATABASE_URL": "sqlite:///app.db"},
    setup=["pip install flask"],
    start=["python app.py"]
)

# Start the environment
with env:
    # Run commands in the isolated environment
    result = env.process.run(["python", "-c", "print('Hello from VirtPy!')"])
    print(result.stdout)
```

Advanced Usage

Network Isolation

```python
# Create environment with network namespace
env = VirtualEnviron(
    name="networked",
    ip="10.0.0.2",
    setup=["apt-get update", "apt-get install -y curl"]
)

with env:
    # Test network connectivity
    if env.test_network_connectivity():
        print("Network is working!")
```

Inter-Process Communication

```python
from virtpy import VirtualEnviron

env = VirtualEnviron(name="ipc-demo")

with env:
    # Processes can communicate via the internal API
    env.internal_api.create_shared_memory("data", 1024)
    
    # Run processes that can talk to each other
    proc1 = env.process.run(["python", "-c", """
        from virtpy import VirtualEnviron
        import time
        # Get API from environment
        print("Process 1 running")
    """])
```

Requirements

· Python 3.8+
· Linux (for network namespace features)
· Root privileges (for network isolation)

Installation from Source

```bash
git clone https://github.com/seuusuario/virtpy.git
cd virtpy
pip install -e .
```

License

MIT

```
