import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- ASCII Banner & Metadata ---
ASCII_BANNER = """
 /$$$$$$$  /$$   /$$  /$$$$$$ 
| $$__  $$| $$  | $$ /$$__  $$
| $$  \\ $$| $$  | $$| $$  \\__/
| $$$$$$$ | $$$$$$$$|  $$$$$$ 
| $$__  $$| $$__  $$ \\____  $$
| $$  \\ $$| $$  | $$ /$$  \\ $$
| $$$$$$$/| $$  | $$|  $$$$$$/
|_______/ |__/  |__/ \\______/ 
------------------------------
Blackhole Sentinel - Production Edition
Made by MLTFR for DN42 Community
"""
print(ASCII_BANNER)

# --- Configuration & Logging ---
LOG_LEVEL_STR = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL_STR, logging.INFO)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("BlackholeSentinel")

ROA_URL = os.getenv("ROA_URL", "https://dn42.burble.com/roa/dn42_roa_46.json")
DATA_DIR = os.getenv("DATA_DIR", ".")
FLAPS_LOG = os.path.join(DATA_DIR, "flaps_log.json")
FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "10"))

app = Flask(__name__)

# --- HTTP Session with Retries & Connection Pooling ---
http_session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
http_session.mount("http://", adapter)
http_session.mount("https://", adapter)

# --- Thread-Safe Cache & File Lock ---
file_lock = threading.Lock()
roa_cache_lock = threading.Lock()

_roa_cache: Dict[str, Any] = {"data": None, "fetched_at": None}


def fetch_upstream_roa() -> Dict[str, Any]:
    """Récupère le ROA brut depuis le serveur amont avec retry automatique.

    En cas d'échec réseau, retombe sur le dernier ROA connu en mémoire cache.
    """
    global _roa_cache
    try:
        resp = http_session.get(ROA_URL, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        with roa_cache_lock:
            _roa_cache = {
                "data": data,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
        logger.debug("ROA amont récupéré avec succès.")
        return data
    except (requests.RequestException, ValueError) as e:
        with roa_cache_lock:
            if _roa_cache["data"] is not None:
                logger.warning(
                    f"Échec fetch ROA upstream ({e}). Utilisation du cache de {_roa_cache['fetched_at']}"
                )
                return _roa_cache["data"]
        logger.error(f"Échec de récupération du ROA amont sans cache disponible: {e}")
        raise


def load_flaps_log() -> Dict[str, Any]:
    """Charge le dictionnaire des flaps depuis le fichier JSON de manière thread-safe."""
    with file_lock:
        if os.path.exists(FLAPS_LOG):
            try:
                with open(FLAPS_LOG, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Erreur lors de la lecture de {FLAPS_LOG}: {e}")
                return {}
        return {}


def save_flaps_log(data: Dict[str, Any]) -> None:
    """Écriture atomique thread-safe pour éviter la corruption du fichier si le processus crash."""
    with file_lock:
        os.makedirs(os.path.dirname(os.path.abspath(FLAPS_LOG)), exist_ok=True)
        tmp_file = FLAPS_LOG + ".tmp"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_file, FLAPS_LOG)
        except OSError as e:
            logger.error(f"Erreur d'écriture dans {FLAPS_LOG}: {e}")
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass
            raise


def load_roa() -> Dict[str, Any]:
    """Fusionne le ROA amont avec les préfixes blackholés (remplace l'ASN par AS0)."""
    roa = fetch_upstream_roa()
    flaps_log = load_flaps_log()

    if not flaps_log:
        return roa

    # Optimisation par ensemble pour la recherche O(1)
    blackholed_prefixes = set(flaps_log.keys())
    for entry in roa.get("roas", []):
        if entry.get("prefix") in blackholed_prefixes:
            entry["asn"] = "AS0"

    return roa


# --- Endpoints HTTP ---

@app.route("/health", methods=["GET"])
def health_check():
    """Endpoint Healthcheck pour Docker et monitoring."""
    return jsonify({"status": "ok", "service": "Blackhole Sentinel"}), 200


@app.route("/roa", methods=["GET"])
def get_roa():
    """Expose le ROA enrichi avec AS0 pour les préfixes instables."""
    try:
        return jsonify(load_roa()), 200
    except (requests.RequestException, ValueError) as e:
        logger.error(f"Service /roa indisponible: {e}")
        return jsonify({"error": f"ROA amont indisponible: {str(e)}"}), 502


@app.route("/flap-alert", methods=["POST"])
def flap_alert():
    """Webhook appelé par flapalerted lors de la détection de flapping."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON invalide ou manquant"}), 400

    prefix = data.get("Prefix")
    total_path_changes = data.get("TotalPathChanges")
    rate_sec = data.get("RateSec")

    if not prefix:
        return jsonify({"error": "Champ 'Prefix' requis"}), 400

    flaps_log = load_flaps_log()

    # Déjà blackholé : mise à jour des métriques uniquement
    if prefix in flaps_log:
        flaps_log[prefix]["total_path_changes"] = total_path_changes
        flaps_log[prefix]["rate_sec"] = rate_sec
        flaps_log[prefix]["updated_at"] = datetime.now(timezone.utc).isoformat()
        save_flaps_log(flaps_log)
        logger.info(f"Préfixe {prefix} déjà blackholé. Métriques mises à jour.")
        return jsonify({"status": "already_blackholed", "prefix": prefix}), 200

    try:
        upstream_roa = fetch_upstream_roa()
    except (requests.RequestException, ValueError) as e:
        return jsonify({"error": f"ROA amont indisponible: {str(e)}"}), 502

    entries = [r for r in upstream_roa.get("roas", []) if r.get("prefix") == prefix]

    if not entries:
        logger.warning(f"Alerte flap reçue pour préfixe non présent dans le ROA: {prefix}")
        return jsonify({"error": f"Préfixe '{prefix}' non trouvé dans le ROA"}), 404

    flaps_log[prefix] = {
        "prefix": prefix,
        "original_entries": [
            {"asn": e.get("asn"), "maxLength": e.get("maxLength")} for e in entries
        ],
        "blackholed_at": datetime.now(timezone.utc).isoformat(),
        "total_path_changes": total_path_changes,
        "rate_sec": rate_sec,
    }
    save_flaps_log(flaps_log)
    logger.warning(f"Préfixe {prefix} mis en trou noir (AS0). Total path changes: {total_path_changes}")

    return jsonify({
        "status": "blackholed",
        "prefix": prefix,
        "total_path_changes": total_path_changes
    }), 200


@app.route("/flap-end", methods=["POST"])
def flap_end():
    """Webhook appelé par flapalerted lors de la stabilisation d'un préfixe."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON invalide ou manquant"}), 400

    prefix = data.get("Prefix")
    if not prefix:
        return jsonify({"error": "Champ 'Prefix' requis"}), 400

    flaps_log = load_flaps_log()

    if prefix not in flaps_log:
        return jsonify({"error": f"Préfixe '{prefix}' non trouvé dans les flaps actifs"}), 404

    del flaps_log[prefix]
    save_flaps_log(flaps_log)
    logger.info(f"Préfixe {prefix} stabilisé et retiré du trou noir (ASN d'origine restauré).")

    return jsonify({"status": "restored", "prefix": prefix}), 200


@app.route("/flaps", methods=["GET"])
def get_flaps():
    """Retourne la liste des préfixes actuellement blackholés."""
    return jsonify(load_flaps_log()), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)