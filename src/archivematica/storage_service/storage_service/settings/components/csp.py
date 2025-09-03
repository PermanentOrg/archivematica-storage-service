from csp.constants import NONE
from csp.constants import SELF
from csp.constants import UNSAFE_EVAL
from csp.constants import UNSAFE_INLINE

CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": [NONE],
        "script-src": [SELF, UNSAFE_INLINE, UNSAFE_EVAL],
        "style-src": [SELF, UNSAFE_INLINE],
        "img-src": [SELF],
        # for the create space form
        "connect-src": [SELF],
    }
}
