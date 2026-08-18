from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.extensions import db
from app.models import Scan
from app.services.url_scanner import analyze_url
from app.services.url_features import extract_url_features

scan_bp = Blueprint(
    "scan",
    __name__,
    url_prefix="/api/v1/scan",
)


@scan_bp.route("/url", methods=["POST"])
@jwt_required()
def scan_url():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body is required",
        }), 400

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "success": False,
            "message": "URL is required",
        }), 400

    if len(url) > 2048:
        return jsonify({
            "success": False,
            "message": "URL is too long",
        }), 400

    try:
        result = analyze_url(url)

        features = extract_url_features(url)

        user_id = int(get_jwt_identity())

        scan = Scan(
            user_id=user_id,
            scan_type="url",
            original_input=url,
            normalized_input=result["normalized_url"],
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            detection_method=result["detection_method"],
            features=features,
        )

        db.session.add(scan)
        db.session.commit()

        return jsonify({
            "success": True,
            "scan": {
                "id": scan.id,
                "type": scan.scan_type,
                "url": scan.original_input,
                "verdict": scan.verdict,
                "risk_score": scan.risk_score,
                "detection_method": scan.detection_method,
                "indicators": result["indicators"],
                "features": features,
                "created_at": scan.created_at.isoformat(),
            },
        }), 200

    except Exception:
        db.session.rollback()

        return jsonify({
            "success": False,
            "message": "Unable to analyze URL",
        }), 500