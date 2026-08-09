from flask import Blueprint, jsonify

api = Blueprint("api", __name__)


@api.route("/")
def home():
    return jsonify({
        "project": "PhishShield AI",
        "status": "Running",
        "version": "1.0.0"
    })


@api.route("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "message": "Backend is running successfully"
    })