import struct
import sys
import volatility.plugins.common as common 
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.plugins.linux.common as linux_common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class linux_volkey(linux_common.AbstractLinuxCommand):
    