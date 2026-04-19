"""v1 API blueprint.

Route handlers are thin: validate input, call a service, return JSON.
No business logic lives here.
"""

from flask import Blueprint

api_v1 = Blueprint("api_v1", __name__, url_prefix="/v1")

# Route modules are imported here to register handlers with the
# blueprint. The imports land at the bottom to keep the blueprint object
# available before the route modules import it.
