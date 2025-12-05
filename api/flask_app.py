"""Thin WSGI wrapper so hosting platforms (like Vercel) can import the Flask app.

This file exposes `app` which is the Flask application defined in `flask_app.py`.
Vercel's Python runtime will use this as the entrypoint for serverless functions.
"""
from flask_app import app

__all__ = ["app"]
