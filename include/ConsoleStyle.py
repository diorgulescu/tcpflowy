import os
import sys


class ConsoleStyle:
    """Provides ANSI terminal color formatting with automatic or manual disable support."""

    ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    @classmethod
    def set_enabled(cls, enabled: bool):
        cls.ENABLED = bool(enabled)

    @classmethod
    def wrap(cls, text, *codes):
        if not cls.ENABLED or not codes:
            return str(text)
        return "".join(codes) + str(text) + cls.RESET

    @classmethod
    def bold(cls, text):
        return cls.wrap(text, cls.BOLD)

    @classmethod
    def dim(cls, text):
        return cls.wrap(text, cls.DIM)

    @classmethod
    def cyan(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.CYAN) if bold else cls.wrap(text, cls.CYAN)

    @classmethod
    def green(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.GREEN) if bold else cls.wrap(text, cls.GREEN)

    @classmethod
    def yellow(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.YELLOW) if bold else cls.wrap(text, cls.YELLOW)

    @classmethod
    def red(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.RED) if bold else cls.wrap(text, cls.RED)

    @classmethod
    def magenta(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.MAGENTA) if bold else cls.wrap(text, cls.MAGENTA)

    @classmethod
    def blue(cls, text, bold=False):
        return cls.wrap(text, cls.BOLD, cls.BLUE) if bold else cls.wrap(text, cls.BLUE)

    @classmethod
    def gray(cls, text):
        return cls.wrap(text, cls.GRAY)

    @classmethod
    def color_app(cls, app_name, is_unknown=False, is_noise=False):
        """Colors the application/protocol classification string padded to 20 chars."""
        padded = f"{str(app_name)[:20]:<20}"
        if is_noise:
            return cls.gray(padded)
        if is_unknown:
            return cls.red(padded, bold=True)
        upper = str(app_name).upper()
        if "TLS" in upper or "HTTPS" in upper or "QUIC" in upper:
            return cls.cyan(padded, bold=True)
        if "HTTP" in upper:
            return cls.green(padded, bold=True)
        if "SSH" in upper or "DNS" in upper or "FTP" in upper or "SMTP" in upper:
            return cls.blue(padded, bold=True)
        return cls.yellow(padded)

    @classmethod
    def color_entropy(cls, entropy_val, label):
        if entropy_val is None:
            return cls.gray("N/A")
        text = f"{entropy_val:.2f} b/B ({label})"
        if entropy_val < 5.0:
            return cls.green(text)
        if entropy_val <= 6.8:
            return cls.yellow(text)
        return cls.magenta(text, bold=True)
