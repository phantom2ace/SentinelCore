from flask import Blueprint, render_template, redirect, url_for
from sqlalchemy.orm import sessionmaker, joinedload
from database import Asset, Vulnerability, Service, engine

app = Blueprint('dashboard', __name__)
Session = sessionmaker(bind=engine)

@app.route('/')
def dashboard():
    session = Session()
    try:
        assets = session.query(Asset).count()
        vulns = session.query(Vulnerability).count()
        high_risk = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 7.0).count()
        return render_template('dashboard.html', 
                               assets=assets, 
                               vulns=vulns,
                               high_risk=high_risk)
    finally:
        session.close()

@app.route('/assets')
def assets_view():
    session = Session()
    try:
        assets = session.query(Asset).all()
        return render_template('assets.html', assets=assets)
    finally:
        session.close()

@app.route('/vulnerabilities')
def vulnerabilities_view():
    session = Session()
    try:
        # FIXED: Use joinedload to eagerly load the asset relationship
        # This prevents the DetachedInstanceError
        vulns = session.query(Vulnerability).options(joinedload(Vulnerability.asset)).all()
        return render_template('vulnerabilities.html', vulnerabilities=vulns)
    finally:
        session.close()

# Blueprint doesn't need the run statement
