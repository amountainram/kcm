import gdb
import subprocess

class RebuildCommand(gdb.Command):
    """Rebuild the project with cargo and reload the binary."""

    def __init__(self):
        super().__init__("rebuild", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.write("Building with cargo...\n")
        result = subprocess.run(
            ["cargo", "build"],
            capture_output=True,
            text=True,
        )

        if result.stdout:
            gdb.write(result.stdout)
        if result.stderr:
            gdb.write(result.stderr)

        if result.returncode != 0:
            gdb.write("Build failed.\n")
            return

        gdb.write("Build succeeded. Reloading binary...\n")
        gdb.execute("file target/debug/kcm")
        gdb.write("Binary reloaded. Use 'run' to start.\n")


RebuildCommand()
gdb.write("Custom command loaded: 'rebuild'\n")
