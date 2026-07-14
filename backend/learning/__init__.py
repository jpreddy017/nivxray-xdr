"""Learning Feedback Loop — boost decoder ranking from Persistent History + KB.

Modules
-------
signals   · Pre-decode content fingerprint (features visible WITHOUT decoding)
booster   · Fingerprint → ranked decoder chain candidates (with source transparency)
feedback  · Per-user chain success counter + thumbs-up-down persistence
"""
