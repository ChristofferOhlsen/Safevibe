"""
detector.py – Smart Port & Tech-Stack Detektion.
Læser package.json, composer.json, requirements.txt, pyproject.toml osv.
for at finde port og identificere tech-stack på tværs af sprog og frameworks.
"""

import os
import json
import re
import socket
from pathlib import Path


COMMON_PORTS = [
    3000,   # Next.js, React, Node
    5173,   # Vite
    4200,   # Angular
    8080,   # Generic HTTP / Spring Boot
    8000,   # Django, FastAPI, Python
    4000,   # Phoenix (Elixir), Sails.js
    3001,   # Create React App fallback, Strapi
    5000,   # Flask, .NET
    5001,   # .NET (HTTPS)
    1337,   # Strapi, Directus
    8090,   # PocketBase
    9000,   # SonarQube, PHP-FPM
    4321,   # Astro
    7860,   # Gradio (Python ML)
    8888,   # Jupyter
]

# JS/TS framework signatures
JS_STACK_SIGNATURES = {
    "Next.js":    ["next", "next.js"],
    "Vite":       ["vite", "@vitejs/plugin-react", "@vitejs/plugin-vue"],
    "React":      ["react", "react-dom"],
    "Vue":        ["vue", "@vue/core", "@vue/runtime-core"],
    "Svelte":     ["svelte", "@sveltejs/kit", "svelte-kit"],
    "Nuxt":       ["nuxt", "@nuxt/core", "nuxt3"],
    "Astro":      ["astro"],
    "Remix":      ["@remix-run/react", "@remix-run/node", "@remix-run/serve"],
    "Angular":    ["@angular/core", "@angular/cli"],
    "Solid":      ["solid-js"],
    "Qwik":       ["@builder.io/qwik"],
    "Express":    ["express"],
    "Fastify":    ["fastify"],
    "Hapi":       ["@hapi/hapi"],
    "Nest.js":    ["@nestjs/core"],
    "Sails.js":   ["sails"],
    "Strapi":     ["@strapi/strapi"],
    "Directus":   ["directus"],
    "Payload":    ["payload"],
    "Electron":   ["electron"],
    "Expo":       ["expo", "react-native"],
    "Gatsby":     ["gatsby"],
    "Nuxt Bridge":["@nuxtjs/composition-api"],
    "SvelteKit":  ["@sveltejs/kit"],
    "Tanstack":   ["@tanstack/router", "@tanstack/start"],
    "tRPC":       ["@trpc/server", "@trpc/client"],
    "GraphQL":    ["graphql", "apollo-server", "@apollo/server"],
    "Prisma":     ["prisma", "@prisma/client"],
    "Drizzle":    ["drizzle-orm", "drizzle-kit"],
}

# Python stack signatures
PYTHON_STACK_SIGNATURES = {
    "Django":     ["django"],
    "Flask":      ["flask"],
    "FastAPI":    ["fastapi"],
    "Tornado":    ["tornado"],
    "Starlette":  ["starlette"],
    "Litestar":   ["litestar"],
    "Sanic":      ["sanic"],
    "Streamlit":  ["streamlit"],
    "Gradio":     ["gradio"],
}

# PHP stack signatures
PHP_STACK_SIGNATURES = {
    "Laravel":    ["laravel/framework"],
    "Symfony":    ["symfony/framework-bundle"],
    "WordPress":  ["wordpress/wordpress"],
    "CakePHP":    ["cakephp/cakephp"],
    "CodeIgniter":["codeigniter4/framework"],
}


def _is_port_open(port: int) -> bool:
    """Tjek hurtigt om en port er åben på localhost."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


def detect_port_from_package_json(project_path: str) -> int | None:
    """Forsøg at udlæse dev-server port fra package.json scripts."""
    pkg_path = os.path.join(project_path, "package.json")
    if not os.path.isfile(pkg_path):
        return None

    try:
        with open(pkg_path, "r", encoding="utf-8") as f:
            pkg = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    scripts = pkg.get("scripts", {})
    for script_name in ["dev", "start", "serve", "preview"]:
        script = scripts.get(script_name, "")
        match = re.search(r"(?:-p|--port|PORT=)\s*(\d{4,5})", script)
        if match:
            return int(match.group(1))
    return None


def has_package_json(project_path: str) -> bool:
    """Returner True hvis der er en package.json i projektmappen."""
    return os.path.isfile(os.path.join(project_path, "package.json"))


def detect_js_stack(project_path: str) -> list[str]:
    """Identificer JS/TS tech-stack ud fra package.json dependencies."""
    pkg_path = os.path.join(project_path, "package.json")
    if not os.path.isfile(pkg_path):
        return []

    try:
        with open(pkg_path, "r", encoding="utf-8") as f:
            pkg = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))
    dep_keys = [k.lower() for k in all_deps.keys()]

    found = []
    for stack_name, sigs in JS_STACK_SIGNATURES.items():
        if any(sig.lower() in dep_keys for sig in sigs):
            found.append(stack_name)

    return found


def detect_python_stack(project_path: str) -> list[str]:
    """Identificer Python framework fra requirements.txt / pyproject.toml."""
    base = Path(project_path)
    found = []

    # requirements.txt
    req_file = base / "requirements.txt"
    if req_file.exists():
        try:
            content = req_file.read_text(encoding="utf-8", errors="ignore").lower()
            for stack_name, sigs in PYTHON_STACK_SIGNATURES.items():
                if any(sig.lower() in content for sig in sigs):
                    found.append(stack_name)
        except OSError:
            pass

    # pyproject.toml
    pyproject = base / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
            for stack_name, sigs in PYTHON_STACK_SIGNATURES.items():
                if not any(s == stack_name for s in found):
                    if any(sig.lower() in content for sig in sigs):
                        found.append(stack_name)
        except OSError:
            pass

    return found


def detect_php_stack(project_path: str) -> list[str]:
    """Identificer PHP framework fra composer.json."""
    composer_path = os.path.join(project_path, "composer.json")
    if not os.path.isfile(composer_path):
        return []

    try:
        with open(composer_path, "r", encoding="utf-8") as f:
            composer = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    all_deps = {}
    all_deps.update(composer.get("require", {}))
    all_deps.update(composer.get("require-dev", {}))
    dep_keys = [k.lower() for k in all_deps.keys()]

    found = []
    for stack_name, sigs in PHP_STACK_SIGNATURES.items():
        if any(sig.lower() in dep_keys for sig in sigs):
            found.append(stack_name)

    return found


def detect_stack(project_path: str) -> tuple[list[str], bool]:
    """
    Identificer tech-stack på tværs af JS/TS, Python og PHP.
    Returnerer (stack_list, has_any_project_file).
    """
    js_stack = detect_js_stack(project_path)
    python_stack = detect_python_stack(project_path)
    php_stack = detect_php_stack(project_path)

    all_stack = js_stack + python_stack + php_stack

    # Tjek om noget er genkendt
    has_project_file = (
        has_package_json(project_path) or
        os.path.isfile(os.path.join(project_path, "requirements.txt")) or
        os.path.isfile(os.path.join(project_path, "pyproject.toml")) or
        os.path.isfile(os.path.join(project_path, "composer.json")) or
        os.path.isfile(os.path.join(project_path, "go.mod")) or
        os.path.isfile(os.path.join(project_path, "Cargo.toml")) or
        os.path.isfile(os.path.join(project_path, "pom.xml")) or
        os.path.isfile(os.path.join(project_path, "build.gradle"))
    )

    return all_stack, has_project_file


def find_active_port(project_path: str) -> int | None:
    """Find den aktive port: prøv package.json-hint først, derefter scan."""
    hint = detect_port_from_package_json(project_path)
    if hint and _is_port_open(hint):
        return hint

    for port in COMMON_PORTS:
        if _is_port_open(port):
            return port

    return None


def run_detection(project_path: str) -> dict:
    """Samlet detektion – returnerer port, stack og project_file status."""
    port = find_active_port(project_path)
    stack, has_project_file = detect_stack(project_path)

    return {
        "port": port,
        "base_url": f"http://localhost:{port}" if port else None,
        "stack": stack,
        "has_project_file": has_project_file,
    }
