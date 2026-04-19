"""v1 API blueprint.

Route handlers are thin: validate input, call a service, return JSON.
No business logic lives here.
"""

from flask import Blueprint

api_v1 = Blueprint("api_v1", __name__, url_prefix="/v1")

# Route modules are imported here to register handlers with the
# blueprint. The imports land at the bottom to keep the blueprint object
# available before the route modules import it.
from knuckles.api.v1 import apple_oauth as _apple_oauth  # noqa: E402, F401
from knuckles.api.v1 import auth as _auth  # noqa: E402, F401 — side-effect import
from knuckles.api.v1 import google_oauth as _google_oauth  # noqa: E402, F401
from knuckles.api.v1 import magic_link as _magic_link  # noqa: E402, F401
from knuckles.api.v1 import passkey as _passkey  # noqa: E402, F401
