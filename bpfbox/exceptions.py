class DaemonNotRunningError(Exception):
    """
    Triggered when the daemon is not running and we attemp to kill it.
    """
    pass
