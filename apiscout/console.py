from rich.console import Console
from rich.theme import Theme

THEME = Theme(
    {
        "banner": "bold cyan",
        "muted": "dim white",
        "target": "bold white",
        "module": "bold blue",
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim white",
        "pass": "bold green",
        "section": "bold white",
    }
)

console = Console(theme=THEME)

BANNER = r"""
  ____  ____  ____  __  ____  ___  __  __ ____
 / _  ||  _ \|  _ \(  )/ ___|/ __)/  \/ /|_  _|
 \ \_| || |_) ) |_) ))(\___ ( (__(  O  <  )(
  \__,_||____/|____/(__)(____/\___)\__/\_\/__\
"""

VERSION = "v0.1.0"


def print_banner() -> None:
    console.print(BANNER, style="banner", highlight=False)
    console.print(
        f"  [muted]{VERSION}  •  API Security Scanner[/muted]\n"
    )
