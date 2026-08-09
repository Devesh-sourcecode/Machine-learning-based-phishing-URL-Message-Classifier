from datetime import datetime

from app.extensions import db


class Scan(db.Model):

    __tablename__ = "scans"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )

    scan_type = db.Column(
        db.String(20),
        nullable=False,
        default="url",
    )

    original_input = db.Column(
        db.Text,
        nullable=False,
    )

    normalized_input = db.Column(
        db.Text,
        nullable=False,
    )

    verdict = db.Column(
        db.String(20),
        nullable=False,
    )

    risk_score = db.Column(
        db.Float,
        nullable=False,
    )

    detection_method = db.Column(
        db.String(50),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "scans",
            lazy=True,
        ),
    )

    def __repr__(self):
        return f"<Scan {self.id} {self.verdict}>"