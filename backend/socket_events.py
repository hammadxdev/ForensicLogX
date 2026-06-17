"""
ForensicLogX — SocketIO Event Handlers
Bridges the RealtimeEngine with connected browser clients.
"""

from flask_socketio import emit


def register(socketio, engine):

    @socketio.on("connect")
    def on_connect():
        snap = engine.get_snapshot()
        emit("snapshot", snap)

    @socketio.on("request_snapshot")
    def on_request_snapshot():
        emit("snapshot", engine.get_snapshot())

    @socketio.on("block_ip")
    def on_block_ip(data):
        ip     = data.get("ip", "")
        actor  = data.get("actor", "Analyst")
        if ip:
            engine.block_ip(ip, actor)
            socketio.emit("ip_blocked", {"ip": ip, "actor": actor})
            socketio.emit("snapshot", engine.get_snapshot())

    @socketio.on("reset_session")
    def on_reset():
        engine.reset()
        socketio.emit("snapshot", engine.get_snapshot())

    # Expose socketio on engine so routes can emit from HTTP handlers
    engine._socketio = socketio


def emit_to_all(engine, event: str, data: dict):
    """Helper called from routes after HTTP agent push."""
    if hasattr(engine, "_socketio"):
        engine._socketio.emit(event, data)
