"""V2-003 (Track E3): application-level audit immutability -- pins that
no API route in this service allows UPDATE/DELETE/bulk-delete/overwrite
of canonical or quarantine audit evidence. Inspects the real FastAPI
app's route table directly (not a hand-maintained list of files), so a
future PR that adds a mutating route anywhere in this service fails
this test rather than silently reintroducing a mutation path.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from api.main import app


def test_every_route_in_this_service_is_read_only():
    """Forbid every route in the app from registering PUT, PATCH, or DELETE."""
    mutating_methods = {"PUT", "PATCH", "DELETE"}
    offenders = []
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "<unknown>")
        if methods & mutating_methods:
            offenders.append((path, methods))
    assert not offenders, (
        f"found route(s) allowing UPDATE/DELETE on the audit service: {offenders} -- "
        f"canonical/quarantine audit evidence must have no ordinary application "
        f"mutation/deletion path (V2-003)"
    )


def test_every_route_is_get_only():
    """Stricter than the above -- this service is, today, entirely
    read/write-via-worker-only at the API layer (no POST either, except
    the pre-existing /audit/test smoke-test route, which writes via the
    normal signed-producer path, not a direct DB mutation). Pins that
    exact shape so any new POST/PUT/PATCH/DELETE route is a deliberate,
    reviewed decision, not an accident."""
    non_get_routes = []
    for route in app.routes:
        methods = (getattr(route, "methods", None) or set()) - {"HEAD", "OPTIONS"}
        path = getattr(route, "path", "<unknown>")
        if methods and methods != {"GET"}:
            non_get_routes.append((path, methods))

    # /audit/test is a known, deliberate exception: it fires a normal
    # signed audit event through AuditLogger.log() (the same producer
    # path every other service uses), not a direct database write --
    # see api/routes_audit.py.
    non_get_routes = [(p, m) for p, m in non_get_routes if p != "/audit/test"]

    assert not non_get_routes, f"unexpected non-GET route(s): {non_get_routes}"
