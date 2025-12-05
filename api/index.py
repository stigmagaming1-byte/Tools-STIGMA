"""Vercel serverless function entry point for Flask API.

This file serves as the main entry point for Vercel serverless functions.
It imports and exposes the Flask app from flask_app.py.
"""

from flask_app import app

# Vercel expects the Flask app to be exposed as 'app'
# This allows Vercel to handle requests through this serverless function
