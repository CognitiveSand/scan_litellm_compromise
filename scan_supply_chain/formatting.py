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


_SEPARATOR_WIDTH = 63


def print_banner(version: str = "") -> None:
    ver_str = f"v{version}" if version else ""
    title = f"Supply Chain Compromise Scanner {ver_str}".strip()
    # Pad title to fill the box (inner width = _SEPARATOR_WIDTH - 3)
    inner = _SEPARATOR_WIDTH - 3
    padded = f"   {title}" + " " * (inner - len(title))
    print(f"{CYAN}{BOLD}")
    print("+" + "=" * _SEPARATOR_WIDTH + "+")
    print(f"|{padded}|")
    print("|   Detects known PyPI and npm supply chain attacks            |")
    print("+" + "=" * _SEPARATOR_WIDTH + "+")
    print(RESET)


def print_separator() -> None:
    print(f"{CYAN}{'-' * _SEPARATOR_WIDTH}{RESET}")


def print_phase_header(number: int, title: str) -> None:
    print(f"\n{BOLD}[Phase {number}] {title}{RESET}\n")


def print_ioc_found(path: str) -> None:
    print(f"  {RED}{BOLD}! FOUND IOC:{RESET} {path}")


def print_clean(message: str = "None found") -> None:
    print(f"  {GREEN}+ {message}{RESET}")


def print_check_header(description: str) -> None:
    print(f"  {BOLD}Checking for {description}...{RESET}")
