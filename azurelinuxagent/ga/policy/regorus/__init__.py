import ctypes
import os
import sys

# Construct the full path to the .so file
so_file_path = os.path.join(os.path.dirname(__file__), 'regorus.cpython-38-x86_64-linux-gnu.so')

# Ensure the .so file is in the system path
sys.path.append(os.path.dirname(so_file_path))

# Load the shared object file
ctypes.CDLL(so_file_path)

# Now import everything from regorus
from .regorus import *

__doc__ = regorus.__doc__
if hasattr(regorus, "__all__"):
    __all__ = regorus.__all__