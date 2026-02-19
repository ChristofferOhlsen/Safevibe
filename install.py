"""
install.py – Installer alle afhængigheder i /lib/ mappen.
Kør én gang: python install.py

Herefter kan du køre: python safevibe <sti-til-projekt>
"""

import subprocess
import sys
import os
import argparse

LIB_DIR = os.path.join(os.path.dirname(__file__), "lib")
BROWSERS_DIR = os.path.join(LIB_DIR, "browsers")

CORE_DEPENDENCIES = [
    "requests",
    "rich",
    "beautifulsoup4",
    "playwright",  # Browser-probe til netværkstrafik + DOM scanning
]


def install_package(name: str, target: str) -> bool:
    """Installer en pakke til target-mappen. Returnerer True ved succes."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install",
         "--target", target,
         "--quiet", "--disable-pip-version-check", name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  ✗ Fejl ved installation af {name}:")
        print(result.stderr[:300])
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Safevibe dependency installer")
    # Behold flags for bagudkompatibilitet men de gør intet ekstra mere
    parser.add_argument("--playwright", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--playwright-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(BROWSERS_DIR, exist_ok=True)

    print(f"📦 Installerer alle afhængigheder i '{LIB_DIR}' ...")
    print("   (Zero-footprint: ingen global pip install)\n")

    for dep in CORE_DEPENDENCIES:
        print(f"  → Installerer {dep}...")
        if install_package(dep, LIB_DIR):
            print(f"  ✓ {dep} installeret")

    print()

    # Installer Chromium browser lokalt i lib/browsers/
    print("🎭 Downloader Chromium browser til lib/browsers/ ...")
    print("   (Kræver ~200MB disk – gemmes kun i dette projekt)\n")

    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = BROWSERS_DIR

    # Playwright er installeret i lib/ – kør via sys.executable med lib/ i path
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, r'{LIB_DIR}'); "
         "from playwright.__main__ import main; main()",
         "install", "chromium"],
        env=env,
        capture_output=False,
        text=True
    )
    if result.returncode == 0:
        print(f"\n  ✓ Chromium installeret i {BROWSERS_DIR}")
    else:
        # Fallback: prøv direkte playwright CLI
        result2 = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            env=env,
            capture_output=True,
            text=True
        )
        if result2.returncode == 0:
            print(f"\n  ✓ Chromium installeret i {BROWSERS_DIR}")
        else:
            print("\n  ⚠ Chromium kunne ikke installeres automatisk.")
            print(f"    Kør manuelt: set PLAYWRIGHT_BROWSERS_PATH={BROWSERS_DIR} && python -m playwright install chromium")

    print()
    print("✅ Færdig! Kør nu:")
    print("   python safevibe                    (scan forældrerprojektet)")
    print("   python safevibe /sti/til/projekt   (scan specifikt projekt)")
    print("   python safevibe --help             (se alle muligheder)\n")


if __name__ == "__main__":
    main()
