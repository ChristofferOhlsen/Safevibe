import sys
import os

# Bootstrap: tilføj /lib/ til sys.path så vendored deps virker uden global pip install
LIB_PATH = os.path.join(os.path.dirname(__file__), "lib")
if LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)

# Sæt Playwright browsers path til lib/browsers/ så alt er zero-footprint lokalt
BROWSERS_PATH = os.path.join(LIB_PATH, "browsers")
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", BROWSERS_PATH)

from engine.cli import run

if __name__ == "__main__":
    run()
