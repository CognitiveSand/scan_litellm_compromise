"""ANSI formatting and display helpers.

Supports Linux terminals natively and enables virtual terminal processing
on Windows 10/11 (cmd.exe, PowerShell). Falls back to plain text if the
terminal does not support ANSI escape codes.
"""

import sys


def _enable_ansi() -> bool:
    """Determine whether the terminal supports ANSI escape codes."""
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False
    return True


_ANSI_ENABLED = _enable_ansi()


def _code(escape: str) -> str:
    return escape if _ANSI_ENABLED else ""


RED = _code("\033[0;31m")
YELLOW = _code("\033[1;33m")
GREEN = _code("\033[0;32m")
CYAN = _code("\033[0;36m")
BOLD = _code("\033[1m")
RESET = _code("\033[0m")


def print_banner(version: str = ""):
    ver_str = f"v{version}" if version else ""
    title = f"Supply Chain Compromise Scanner {ver_str}".strip()
    # Pad title to fill the box (59 chars inner width)
    padded = f"   {title}" + " " * (60 - len(title) - 3)
    print(f"{CYAN}{BOLD}")
    print("+" + "=" * 63 + "+")
    print(f"|{padded}|")
    print("|   Detects known PyPI and npm supply chain attacks            |")
    print("+" + "=" * 63 + "+")
    print(RESET)


def print_separator():
    print(f"{CYAN}{'-' * 63}{RESET}")


def print_phase_header(number: int, title: str):
    print(f"\n{BOLD}[Phase {number}] {title}{RESET}\n")


def print_ioc_found(path: str):
    print(f"  {RED}{BOLD}! FOUND IOC:{RESET} {path}")


def print_clean(message: str = "None found"):
    print(f"  {GREEN}+ {message}{RESET}")


def print_check_header(description: str):
    print(f"  {BOLD}Checking for {description}...{RESET}")
