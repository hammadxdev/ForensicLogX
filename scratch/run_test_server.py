import sys
import os

# Add workspace to path
sys.path.insert(0, r"e:\ForensicLogX")

from app import create_app

PORT = 5558
app, sio = create_app()

print(f"[SERVER] Starting test server on port {PORT}...")
try:
    sio.run(app, debug=False, host="127.0.0.1", port=PORT, allow_unsafe_werkzeug=True)
except Exception as e:
    print(f"[SERVER ERROR] Failed to start server: {e}")
    sys.exit(1)
