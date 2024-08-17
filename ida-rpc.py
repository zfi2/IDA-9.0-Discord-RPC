import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_name
import ida_nalt
import time
from pypresence import Presence

PLUGIN_NAME = "Discord RPC for IDA"
PLUGIN_HOTKEY = "Ctrl-Alt-D"
PLUGIN_COMMENT = "Display IDA status in Discord"
PLUGIN_HELP = "This plugin updates your Discord status with IDA information"
PLUGIN_VERSION = "1.0"

CLIENT_ID = "1274210451273551973"
THROTTLE_TIME = 5  # Minimum time between updates in seconds

class DiscordRPCPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        self.rpc = None
        self.running = False
        self.hook = None
        self.last_func_name = None
        self.last_update_time = 0
        self.update_pending = False
        self.start_time = int(time.time())

    def init(self):
        self.start_rpc()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Toggle RPC on/off
        if self.running:
            self.stop_rpc()
        else:
            self.start_rpc()

    def term(self):
        self.stop_rpc()

    def start_rpc(self):
        if not self.running:
            try:
                self.rpc = Presence(CLIENT_ID)
                self.rpc.connect()
                self.running = True
                self.hook = IDAViewHook(self)
                self.hook.hook()
                self.update_presence(force=True)
                print(f"{PLUGIN_NAME} started")
            except Exception as e:
                print(f"Error starting {PLUGIN_NAME}: {str(e)}")

    def stop_rpc(self):
        if self.running:
            self.running = False
            if self.hook:
                self.hook.unhook()
            if self.rpc:
                self.rpc.close()
            print(f"{PLUGIN_NAME} stopped")

    def update_presence(self, force=False):
        if not self.running:
            return

        current_time = time.time()
        if not force and current_time - self.last_update_time < THROTTLE_TIME:
            if not self.update_pending:
                self.update_pending = True
                ida_kernwin.register_timer(THROTTLE_TIME * 1000, self._delayed_update)
            return

        self._perform_update()

    def _delayed_update(self):
        self.update_pending = False
        self._perform_update()
        return -1  # Unregister the timer

    def _perform_update(self):
        try:
            current_function = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if current_function:
                func_name = ida_name.get_ea_name(current_function.start_ea)
            else:
                func_name = "No function"

            if func_name != self.last_func_name:
                self.last_func_name = func_name
                file_name = ida_nalt.get_root_filename()

                self.rpc.update(
                    details=f"Analyzing: {file_name}",
                    state=f"Function: {func_name}",
                    large_image="ida_logo",
                    large_text="IDA Pro 9.0",
                    start=self.start_time
                )
                print(f"Updated presence: {file_name} - {func_name}")  # Debug print
                self.last_update_time = time.time()
        except Exception as e:
            print(f"Error updating presence: {str(e)}")

class IDAViewHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin

    def screen_ea_changed(self, ea, prev_ea):
        self.plugin.update_presence()
        return 0

def PLUGIN_ENTRY():
    return DiscordRPCPlugin()