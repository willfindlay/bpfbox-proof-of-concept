import os
import sys
import subprocess


def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """

    def inner(*args, **kwargs):
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ["SUDO_UID"])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ["SUDO_GID"])
        except (KeyError, ValueError):
            print("Could not get GID for sudoer", file=sys.stderr)
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret

    return inner


def which(binary):
    try:
        w = subprocess.Popen(
            ["which", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        res = w.stdout.readlines()
        if len(res) == 0:
            raise Exception(f"{binary} not found")
        return os.path.realpath(res[0].strip())
    except Exception:
        if os.path.isfile(binary):
            return os.path.realpath(binary)
        else:
            raise Exception(f"{binary} not found")