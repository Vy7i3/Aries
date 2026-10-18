"""Banner and pixel-art black goat for ARIES."""

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.style import Style

# White → light grey → mid grey → dark grey gradient
GRADIENT = [
    "#FFFFFF",
    "#E8E8E8",
    "#C8C8C8",
    "#A8A8A8",
    "#888888",
    "#686868",
    "#484848",
]

# Dense pixel-art black goat inspired by the photo
GOAT_PIXEL = r"""
                                                                   
                                              -=-                  
                                         :.:--=+*+++*#             
                    =--::=+           *-.:=*#++*#****###%          
                   #*+=-::-+*       *-:-+*+=#**+*#####***##        
                    %##*-..:*      -:-=+***++##       %%#++#       
                      %-=+++*    --+*++*++*#             %#**%     
                       =-+=+*#   ++==+#++#             --  ##+     
           -==-        +=:-=+-.:=-:-=+**+*        :-==+=-  =-=+    
           -++=+--     =:....:=:::..-=++=+#    *-=**+=+=-  =:-+    
            =++*#+:.:  -::-:=::---:++=---=:-==.:=#%#+++-   =--*    
             -=*#%*==::------::=-::--::..-=:.:-+###*+=-    ==*%    
              --####+..:--.:---.--=:..:..:--=*+%%*+=-      *=%     
                 =++..::=-....:-:=-.::----*####*++                 
                   --::-::.:..:.-=-.:-=+*#*##*===                  
                   %:---.::::-:.:++:-+%*#+**##=:-==                
                     =*..:-::---::*:=+*+**++#*=---+                
                     *-:..:::---:+*++=+*+-==++=--:=-::.:..:=-      
                     =:....-=-=-:=+==+*=--=====--:--::::.....:     
                     +:...:---:--==+====--+=*+=:::-=:--::.::..:    
                     =...:::-=-:===-=-:-:=====-:::---::.......:    
                     :....:.:.:-==+===+:::-=+--::---=--.::..::     
                    -......:-:-++=+===-.:-=-+=:::--:---:.....      
                    :.......:-==--=----::-+++::-:::.--:-.:...      
                    :.:....:.-=====----:==**+-:--:----=-:....      
                    --==+*#-.:=+===--=-=++**+---.:--:.--:.:..      
                   ::++*#-...::-=-==****#%##+=-::-::::---...:      
                   :.:+:.:---*-+*+*%%##***##*+=---------:..:       
                    --+++++*=-=# #%%%##*+**##*+=-:-:-:--:...       
                     -=++==-==   *#####******+=-:----=-:....       
                        -=====     ***##+++*++==--=-=-:....-       
                         ---         =***==++**==::-=-:::.::       
                                     -=+**++*##+=-----:::--:       
                                     -=+*****##+=-:--=:-           
                                      ---****#*=------             
                                       --  +=+=  : -               
"""

# User-provided ARIES logo (FIGLET-style)
TITLE_LINES = [
    r"     /\  \         /\  \          ___        /\  \         /\  \    ",
    r"    /::\  \       /::\  \        /\  \      /::\  \       /::\  \   ",
    r"   /:/\:\  \     /:/\:\  \       \:\  \    /:/\:\  \     /:/\ \  \  ",
    r"  /::\~\:\  \   /::\~\:\  \      /::\__\  /::\~\:\  \   _\:\~\ \  \ ",
    " /:/\\:\\ \\:\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/\\:\\ \\:\\__\\ /\\ \\:\\ \\ \\__\\",
    r" \/__\:\/:/  / \/_|::\/:/  / /\/:/  /    \:\~\:\ \/__/ \:\ \:\ \/__/",
    r"      \::/  /     |:|::/  /  \::/__/      \:\ \:\__\    \:\ \:\__\  ",
    r"      /:/  /      |:|\/__/    \:\__\       \:\ \/__/     \:\/:/  /  ",
    r"     /:/  /       |:|  |       \/__/        \:\__\        \::/  /   ",
    r"     \/__/         \|__|                     \/__/         \/__/    ",
]


def _gradient_text(text: str, colors: list[str]) -> Text:
    result = Text()
    if not text:
        return result
    n = len(text)
    n_colors = len(colors)
    for i, ch in enumerate(text):
        t = i / max(n - 1, 1)
        idx = t * (n_colors - 1)
        lo = int(idx)
        hi = min(lo + 1, n_colors - 1)
        color = colors[lo] if (idx - lo) < 0.5 else colors[hi]
        result.append(ch, style=Style(color=color, bold=True))
    return result


def make_title() -> Text:
    lines = [_gradient_text(line, GRADIENT) for line in TITLE_LINES]
    return Text("\n").join(lines)


def make_goat() -> Text:
    """ASCII goat as provided — left-aligned, not stretched."""
    goat = Text()
    for line in GOAT_PIXEL.splitlines():
        goat.append(line + "\n", style=Style(color="#A0A0A0", bold=True))
    return goat


def render_banner(console: Console, version: str = "1.0.0") -> None:
    title = make_title()
    goat = make_goat()

    header = Group(
        Align.center(Text("ARIES — System Auditing Terminal", style="bold #E0E0E0")),
        Text(""),
        Align.center(title),
        Text(""),
        Align.center(goat),
        Text(""),
        Align.center(
            Text(
                f"v{version}  •  Arch Linux  •  Interactive Audit",
                style="dim #808080",
            )
        ),
    )

    panel = Panel(
        header,
        border_style="#505050",
        padding=(1, 2),
        title="[bold #C0C0C0]ARIES[/]",
        title_align="left",
        subtitle="[dim]black goat of the system[/]",
        subtitle_align="right",
    )
    console.print(panel)
    console.print()


def render_compact_banner(console: Console) -> None:
    """Smaller banner for menu returns."""
    console.print(Align.center(make_title()))
    console.print(
        Align.center(Text("ARIES  •  interactive mode", style="dim #808080"))
    )
    console.print()
