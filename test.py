# uncompyle6 version 3.9.2
# Python bytecode version base 3.7.0 (3394)
# Decompiled from: Python 3.10.1 (tags/v3.10.1:2cd268a, Dec  6 2021, 19:10:37) [MSC v.1929 64 bit (AMD64)]
# Embedded file name: av.py
import os, sys, subprocess
from subprocess import Popen, PIPE
import lief
from io import StringIO as sio
exist = os.path.exists
rmfile = os.remove
isfile = os.path.isfile
basename = os.path.basename
dirname = os.path.dirname
pin = os.path.join

def shell():
    import IPython
    IPython.embed()


def set_python_path(*paths):
    import sys, os
    isfile = os.path.isfile
    isdir = os.path.isdir
    dirname = os.path.dirname
    abspath = os.path.abspath
    if paths:
        for i in paths[:-1]:
            if isfile(i):
                sys.path.insert(0, dirname(i))

    sys.path.insert(0, dirname(abspath(sys.argv[0])))


def wt(file_path='@@@bin@@@', mode='wb'):
    return (lambda data: open(file_path, mode).write(data))


def rd(file_path='@@@bin@@@', mode='rb'):
    import chardet
    if mode == "rb":
        print("123")
        return open(file_path, mode).read()
    if mode == "r":
        print("456")
        content = open(file_path, "rb").read()
        return content.decode(chardet.detect(content)["encoding"])
    return


def has_ch(data):
    for i in data:
        if "一" <= i <= "\u9fff":
            return True

    return False


def pp(*command):

    def communicate(c_input=b''):
        st = subprocess.STARTUPINFO()
        st.dwFlags = subprocess.STARTF_USESHOWWINDOW
        st.wShowWindow = subprocess.SW_HIDE
        p_pipe = subprocess.Popen((list(command)), stdin=(subprocess.PIPE), stdout=(subprocess.PIPE), startupinfo=st)
        return p_pipe.communicate(c_input)[0]

    return communicate


class px(object):

    def __init__(self):
        self.data = b''

    def __call__(self, *args):
        self.data = pp(*args)(self.data)
        return self

    @property
    def val(self):
        return self.data

    @val.setter
    def val(self, data):
        self.data = data


px = px()

class pe(object):

    def __init__(self, pe_obj):
        if type(pe_obj) == lief.PE.Binary:
            self.pe_obj = pe_obj
            print("进入类第零分支")
        else:
            self.pe_obj = lief.parse(pe_obj)
            print("进入类第一分支")
            # try:
            #     print(f"EEEEEEE  {self.isdll} {self.isdrv}")
            # except(e):
            #     print(e)
            if type(self.pe_obj) != lief.PE.Binary:
                print("进入类第二分支")
                raise ValueError("invalid pe file")

    @property
    def lf(self):
        return self.pe_obj

    def wt(self, name):
        self.pe_obj.write(name)

    def ro(self, rva):
        return self.pe_obj.rva_to_offset(rva)

    def vo(self, va):
        return self.pe_obj.va_to_offset(va)

    @property
    def bs(self):
        return self.pe_obj.optional_header.imagebase

    @bs.setter
    def bs(self, addr):
        self.pe_obj.optional_header.imagebase = addr

    @property
    def h(self):
        return self.pe_obj.header

    @property
    def oh(self):
        return self.pe_obj.optional_header

    @property
    def dd(self):
        return list(self.pe_obj.data_directories)

    @property
    def ep(self):
        return self.pe_obj.optional_header.addressof_entrypoint

    @ep.setter
    def ep(self, addr):
        self.pe_obj.optional_header.addressof_entrypoint = addr

    @property
    def sub(self):
        return self.oh.subsystem

    @sub.setter
    def sub(self, flag):
        if flag.strip().startswith("n"):
            self.oh.subsystem = lief.PE.SUBSYSTEM.NATIVE
        if flag.strip().startswith("c"):
            self.oh.subsystem = lief.PE.SUBSYSTEM.WINDOWS_CUI
        if flag.strip().startswith("g"):
            self.oh.subsystem = lief.PE.SUBSYSTEM.WINDOWS_GUI

    @property
    def cui(self):
        return self.oh.subsystem == lief.PE.SUBSYSTEM.WINDOWS_CUI

    @property
    def gui(self):
        return self.oh.subsystem == lief.PE.SUBSYSTEM.WINDOWS_GUI

    @property
    def nt(self):
        return self.oh.subsystem == lief.PE.SUBSYSTEM.NATIVE

    @property
    def arch(self):
        return self.pe_obj.header.machine

    @property
    def inf(self):
        return "\n".join(["PE " + str(self.arch).split(".")[-1], "Base: " + hex(self.bs), "EP(RVA): " + hex(self.ep), "EP(RAW): " + hex(self.ro(self.ep)), "PIE: " + str(self.pie), str(self.pe_obj.optional_header.subsystem), "CheckSum: {}".format(hex(self.pe_obj.optional_header.checksum))])

    @property
    def is32(self):
        return self.pe_obj.header.machine == lief.PE.MACHINE_TYPES.I386

    @property
    def is64(self):
        return self.pe_obj.header.machine == lief.PE.MACHINE_TYPES.AMD64

    @property
    def isdll(self):
        return lief.PE.Header.CHARACTERISTICS.DLL in self.pe_obj.header.characteristics_list

    @property
    def isdrv(self):
        print("test?")
        return self.pe_obj.optional_header.subsystem == lief.PE.SUBSYSTEM.NATIVE

    @property
    def isexe(self):
        print("EEEEEEEEEEEEEEEE")
        # print(f"{self.pe_obj}")
        # print(f"{self.pe_obj.isdll}")
        print(f"是否为dll：{self.isdll}")

        # print(f"  {self.isdll}   {self.isdrv}")
        return not self.isdll and not self.isdrv

    @property
    def nx(self):
        return self.pe_obj.has_nx

    @property
    def pie(self):
        return self.pe_obj.is_pie

    @property
    def safe_seh(self):
        pass

    @property
    def cfg(self):
        return lief.PE.DLL_CHARACTERISTICS.GUARD_CF in self.pe_obj.optional_header.dll_characteristics_lists

    @property
    def no_seh(self):
        return lief.PE.DLL_CHARACTERISTICS.NO_SEH in self.pe_obj.optional_header.dll_characteristics_lists

    @property
    def h_seh(self):
        return not self.no_seh

    @property
    def h_sig(self):
        return self.pe_obj.has_signature

    @property
    def h_rel(self):
        return self.pe_obj.has_relocations

    @property
    def h_res(self):
        return self.pe_obj.has_resources

    @property
    def h_tls(self):
        return self.pe_obj.has_tls

    @property
    def h_im(self):
        return self.pe_obj.has_imports

    @property
    def h_ex(self):
        return self.pe_obj.has_exports

    @property
    def h_cfg(self):
        return self.pe_obj.has_configuration

    @property
    def h_exc(self):
        return self.pe_obj.has_exceptions

    @property
    def h_dbg(self):
        return self.pe_obj.has_debug

    @property
    def ex(self):

        class ent:

            def __init__(self, ord, name, addr):
                self.ord = ord
                self.name = name
                self.addr = addr

            def __str__(self):
                return "{: >5} 0x{:0>8X}  {}".format(self.ord, self.addr, self.name)

        return [ent(i.ordinal, i.name, i.address) for i in self.pe_obj.get_export().entries]

    def s_ex(self, target=''):
        img = self.pe_obj
        return img and img.has_exports or ""
        img_ex = img.get_export()
        ret = sio("")
        for i in img_ex.entries:
            print(("{}{: >5} 0x{:0>8X}  {}".format(target, i.ordinal, i.address, i.name)), file=ret)

        return ret.getvalue()

    def s_im(self, target=''):
        img = self.pe_obj
        if not img:
            return
        ret = sio("")
        for i in img.imports:
            for j in i.entries:
                print(("{} mod: {} | iat: 0x{:0>8X} | {}".format(target, i.name, j.iat_address, "ord: " + hex(j.ordinal) if j.is_ordinal else "name: " + j.name)), file=ret)

        return ret.getvalue()

    def dlfw(self, old_name):
        img = self.pe_obj
        return img and img.has_exports or None
        old_name = old_name.split(".")[0]
        img_ex = img.get_export()
        ret = sio("")
        for i in img_ex.entries:
            if i.name:
                if i.name[0] == "_":
                    print(('#pragma comment(linker, "/export:{}={}.{},@{}")'.format("_" + i.name, old_name, i.name, i.ordinal)), file=ret)
                else:
                    print(('#pragma comment(linker, "/export:{}={}.{},@{}")'.format(i.name, old_name, i.name, i.ordinal)), file=ret)
            else:
                print(('#pragma comment(linker, "/export:ord{}={}.#{},@{},NONAME")'.format(i.ordinal, old_name, i.ordinal, i.ordinal)), file=ret)

        return ret.getvalue()

    @property
    def dlib(self):
        return self.pe_obj.libraries


def exe(exe_obj):
    if type(exe_obj) == str:
        print(f"type={type(exe_obj)} {exe_obj}")
        if not isfile(exe_obj):
            print("1")
            return
        elif has_ch(exe_obj):
            print("2")
            exe_obj = rd(exe_obj)
        else:
            print("3")
            exe_obj = lief.parse(exe_obj)
        if not exe_obj:
            print("4")
            return
    
    try:
        print("尝试返回PE类")
        return pe(exe_obj)
    except:
        pass


def ispe(pe_path):
    if type(exe(pe_path)) == pe:
        print("TTTTTTTTTTTT")
        return True
    print("FFFFFFFFFFFFF")
    return False


def pe2sc(target):
    try:
        if type(target) == str:
            print("分支1")
            if exist(target):
                print("分支1-1")
                data = rd(target)
                # print(f"分支data{data}")
            else:
                if type(target) == bytes:
                    print("分支1-2")
                    data = target
                else:
                    print("分支1-3")
                    return b''
            # print(f"{exe(data).isexe}")
        if exe(data).isexe:
            print("分支2")
            binx_path = "@@@bin@@@.exe"
        else:
            if exe(data).isdll:
                print("分支3")
                binx_path = "@@@bin@@@.dll"
            else:
                print("分支4")
                return b''
        bin_path = "@@@bin@@@"
        print(f"进行写入{binx_path} {data}")
        wt(binx_path)(data)
        print("结束运行")
        px(pin(src_path("av_lib"), "dddd.exe"), "-f", binx_path, "-o", bin_path)
        rmfile(binx_path)
        data = rd(bin_path)
        rmfile(bin_path)
        print("结束运行")
        return data
    except:
        return b''


def esc(target):
    if type(target) == bytes:
        data = target
    else:
        if type(target) == str and exist(target) == True:
            data = rd(target)
        else:
            raise ValueError("Invalid target")
    data = list(data)
    for i in range(len(data)):
        data[i] = (data[i] + i % 256) % 256

    return bytes(data)


def wtz(file_path='@@@bin@@@', mode='a'):
    import zipfile
    return (lambda name, data: zipfile.ZipFile(file_path, mode).writestr(name, data, compress_type=None, compresslevel=None))


def src_path(relative_path):
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return pin(base_path, relative_path)


def main():
    if len(sys.argv) < 2:
        print("useage: [file path]")
        return
    elif ispe(sys.argv[1]):
        print("进入加密")
        x = pe2sc(sys.argv[1])
    else:
        print("进入rd")
        x = rd(sys.argv[1])
    x = esc(x)
    file_list = [
     "av_lib\\version.dll",
     "av_lib\\versionx.dll",
     "av_lib\\cui.exe"]
    out_name = "av.zip"
    if exist(out_name):
        rmfile(out_name)
    wtz(out_name)("cui.cfg", x)
    for i in file_list:
        wtz(out_name)(basename(i), rd(src_path(i)))


if __name__ == "__main__":
    main()

# okay decompiling av.pyc
