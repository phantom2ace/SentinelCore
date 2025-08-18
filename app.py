# app.py
import os
from flask import Flask, render_template
from database import Asset, Vulnerability, Service
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from dashboard import dashboard

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sentinel_core.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key_for_testing')
    
    from dashboard import app as dashboard_blueprint
    app.register_blueprint(dashboard_blueprint)
    
    from api import api
    app.register_blueprint(api)
    
    @app.route('/')
    def index():
        return render_template('dashboard.html')
    
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500
    
    @app.context_processor
    def inject_stats():
        from database import engine
        Session = sessionmaker(bind=engine)
        session = Session()
        
        try:
            asset_count = session.query(Asset).count()
            vuln_count = session.query(Vulnerability).count()
            high_risk = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 7.0).count()
            avg_cvss = session.query(func.avg(Vulnerability.cvss_score)).scalar() or 0
            
            return dict(
                asset_count=asset_count,
                vuln_count=vuln_count,
                high_risk=high_risk,
                avg_cvss=round(avg_cvss, 1)
            )
        finally:
            session.close()
    
    return app

# Create the app instance for gunicorn
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
