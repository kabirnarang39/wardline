package wardline.authz

# Denies every call: no allow rule ever fires, so every request falls
# through to this default. Add allow rules below as you grant access.
default allow = false
