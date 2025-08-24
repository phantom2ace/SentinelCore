from flask import Blueprint, render_template, redirect, url_for
from sqlalchemy.orm import sessionmaker, joinedload
from database import Asset, Vulnerability, Service, engine

app = Blueprint('dashboard', __name__)
Session = sessionmaker(bind=engine)

@app.route('/')
def dashboard():
    # No need to query stats here as they are provided by the context processor in app.py
    return render_template('dashboard.html')

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

@app.route('/remediation')
def remediation_view():
    session = Session()
    try:
        # Get vulnerabilities that need remediation (CVSS >= 4.0)
        remediation_items = session.query(Vulnerability).options(joinedload(Vulnerability.asset))\
            .filter(Vulnerability.cvss_score >= 4.0).all()
        
        # Get isolated assets
        isolated_assets = session.query(Asset).filter(Asset.isolated == True).all()
        
        # Auto-remediation threshold (would normally come from settings)
        auto_remediation_threshold = 9.0
        
        # Count of auto-remediated vulnerabilities
        auto_remediated_count = session.query(Vulnerability)\
            .filter(Vulnerability.remediated == True)\
            .filter(Vulnerability.auto_remediated == True).count()
            
        return render_template('remediation.html',
                              remediation_items=remediation_items,
                              isolated_assets=isolated_assets,
                              auto_remediation_threshold=auto_remediation_threshold,
                              auto_remediated_count=auto_remediated_count)
    finally:
        session.close()

# Blueprint doesn't need the run statement
