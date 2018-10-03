from argparse import ArgumentParser

import frida

# cli = ArgumentParser()

# def argument(*args, **kwargs):
#     def decorator(func):
#         if "help" not in kwargs:
#             kwargs["help"] = func.__doc__

#         cli.add_argument(*args, **kwargs)

#         return func
#     return decorator

# @argument("-p", "--attach-pid", type=int)
# def main():
#     args = cli.parse_args()
#     session = frida.attach(args.attach_pid)
#     # script = session.create_script(src)
#     # script.load()
#     return session


class FridaWrap(object):
    def __init__(self, device=None, target=None):
        self.args = None
        self.parser = ArgumentParser()
        self.session = None
        self.script = None
        self.target = None

        if not device:
            self.parser.add_argument("-D", "--device", help="connect to device with the given ID", metavar="ID", action="store", dest="device_id", default=None)
            self.parser.add_argument("-U", "--usb", help="connect to USB device", action="store_const", const="usb", dest="device_type", default=None)
            self.parser.add_argument("-R", "--remote", help="connect to remote frida-server", action="store_const", const="remote", dest="device_type", default=None)
            self.parser.add_argument("-H", "--host", help="connect to remote frida-server on HOST", metavar="HOST", action="store", dest="host", default=None)

        if not target:
            # def store_target(option, opt_str, target_value, parser, target_type, *args, **kwargs):
            #     if target_type == "file":
            #         target_value = [target_value]
            #     setattr(parser.values, "target", (target_type, target_value))

            # self.parser.add_argument("-f", "--file", help="spawn FILE", metavar="FILE", type="string", action="callback", callback=store_target, callback_args=("file",))
            # self.parser.add_argument("-n", "--attach-name", help="attach to NAME", metavar="NAME", action="callback", callback=store_target, callback_args=("name",))
            # self.parser.add_argument("-p", "--attach-pid", help="attach to PID", metavar="PID", type=int, action="callback", callback=store_target, callback_args=("pid",))
            self.parser.add_argument("-p", "--attach-pid", help="attach to PID", metavar="PID", type=int, action="store", dest="target_pid", default=None)
            self.parser.add_argument("--debug", help="enable the Node.js compatible script debugger", action="store_true", dest="enable_debugger", default=False)
            self.parser.add_argument("--enable-jit", help="enable JIT", action="store_true", dest="enable_jit", default=False)

    def parse(self):
        self.args = self.parser.parse_args()
        self.target = self.args.target_pid
        return self.args

    def attach(self):
        if self.args is None:
            self.parse()

        self.session = frida.attach(self.target)
        return self.session

    def load_script(self, src):
        if self.session is None:
            self.attach()

        self.script = self.session.create_script(src)
        self.script.load()

        return self.script


if __name__ == "__main__":
    wrap = FridaWrap()
    wrap.load_script("rpc.exports={a:function(){return 'aaa'}}")
    print(wrap.script.exports.a())
