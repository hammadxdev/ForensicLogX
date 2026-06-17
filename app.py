"""
ForensicLogX — Main Flask Application with Real-Time SocketIO
BS Digital Forensics & Cyber Security — Final Year Project
Student: Gohar Ali | Roll: FA-22-BSDFCS-095
"""

from flask import Flask
from flask_socketio import SocketIO
from backend.routes import main_bp
from backend.realtime_engine import RealtimeEngine
from backend.config import Config
import os
import threading

socketio = SocketIO()
realtime_engine = RealtimeEngine()

def create_app():
    app = Flask(__name__, template_folder="frontend/templates", static_folder="frontend/static")
    app.config.from_object(Config)

    for folder in [app.config["UPLOAD_FOLDER"], app.config["REPORT_FOLDER"], app.config["HASH_FOLDER"]]:
        os.makedirs(folder, exist_ok=True)

    app.realtime_engine = realtime_engine
    
    app.sigma_rules = []  # populated by background thread

    def _load_rules_bg():
        from backend.sigma_engine import load_sigma_rules
        rules = load_sigma_rules("dataset/sigma")
        app.sigma_rules = rules

    t = threading.Thread(target=_load_rules_bg, daemon=True, name="sigma-loader")
    t.start()
    
    app.register_blueprint(main_bp)

    # ── CRS routes (separate blueprint) ────────────────────────────────────────
    from backend.crs_routes import crs_bp
    app.register_blueprint(crs_bp)

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    from backend import socket_events
    socket_events.register(socketio, realtime_engine)

    return app, socketio


if __name__ == "__main__":
    app, sio = create_app()
    print("\n" + "="*60)
    print("  ForensicLogX — Linux Log Analyzer (Real-Time Mode)")
    print("  BS Digital Forensics & Cyber Security")
    print("  Student: Gohar Ali | FA-22-BSDFCS-095")
    print("="*60)
    print(f"  Dashboard  : http://127.0.0.1:5000")
    print(f"  Agent Push : http://127.0.0.1:5000/api/agent/push")
    print(f"  CRS API    : http://127.0.0.1:5000/api/crs-rules")
    print("="*60 + "\n")
    sio.run(app, debug=False, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
