from flask import Blueprint, render_template, redirect, url_for
from sqlalchemy.orm import sessionmaker
from database import Asset, Vulnerability, Service, engine

app = Blueprint('dashboard', __name__)
Session = sessionmaker(bind=engine)

@app.route('/')
def dashboard():
    session = Session()
    assets = session.query(Asset).count()
    vulns = session.query(Vulnerability).count()
    high_risk = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 7.0).count()
    session.close()
    return render_template('dashboard.html', 
                           assets=assets, 
                           vulns=vulns,
                           high_risk=high_risk)

@app.route('/assets')
def assets_view():
    session = Session()
    assets = session.query(Asset).all()
    session.close()
    return render_template('assets.html', assets=assets)

@app.route('/vulnerabilities')
def vulnerabilities_view():
    session = Session()
    vulns = session.query(Vulnerability).join(Asset).all()
    session.close()
    return render_template('vulnerabilities.html', vulnerabilities=vulns)

# Blueprint doesn't need the run statement