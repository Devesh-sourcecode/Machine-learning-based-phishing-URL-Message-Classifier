from flask import Blueprint, jsonify, request
from flask_bcrypt import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required

from app.extensions import db
from app.models import User


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/v1/auth",
)


@auth_bp.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body is required",
        }), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({
            "success": False,
            "message": "Username, email and password are required",
        }), 400

    if len(password) < 8:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 8 characters",
        }), 400

    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        return jsonify({
            "success": False,
            "message": "Username or email already exists",
        }), 409

    password_hash = generate_password_hash(password).decode("utf-8")

    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "User registered successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Request body is required",
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required",
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(
        user.password_hash,
        password,
    ):
        return jsonify({
            "success": False,
            "message": "Invalid email or password",
        }), 401

    if not user.is_active:
        return jsonify({
            "success": False,
            "message": "User account is inactive",
        }), 403

    access_token = create_access_token(
        identity=str(user.id)
    )

    return jsonify({
        "success": True,
        "message": "Login successful",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():

    user_id = get_jwt_identity()

    user = db.session.get(User, int(user_id))

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found",
        }), 404

    return jsonify({
        "success": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
        },
    }), 200