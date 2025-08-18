from flask import Blueprint, jsonify, request
from database import Asset, Vulnerability, Service, Session
from sqlalchemy.orm import joinedload
from sqlalchemy import func
import logging
from enforcement import isolate_asset, restore_asset
from policy_engine import calculate_risk, generate_recommendations, generate_compliance_report

api = Blueprint('api', __name__, url_prefix='/api')
logger = logging.getLogger('API')

@api.route('/assets', methods=['GET'])
def get_assets():
    """Get all assets or filter by IP"""
    session = Session()
    ip_filter = request.args.get('ip')
    
    try:
        if ip_filter:
            assets = session.query(Asset).filter(Asset.ip.like(f"%{ip_filter}%")).all()
        else:
            assets = session.query(Asset).all()
        
        return jsonify({
            'status': 'success',
            'count': len(assets),
            'assets': [{
                'id': asset.id,
                'ip': asset.ip,
                'hostname': asset.hostname,
                'os': asset.os,
                'type': asset.type,
                'cloud_provider': asset.cloud_provider
            } for asset in assets]
        })
    except Exception as e:
        logger.error(f"Error retrieving assets: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        session.close()

@api.route('/assets/<int:asset_id>', methods=['GET'])
def get_asset(asset_id):
    """Get a specific asset by ID"""
    session = Session()
    
    try:
        asset = session.query(Asset).options(
            joinedload(Asset.services),
            joinedload(Asset.vulnerabilities)
        ).filter(Asset.id == asset_id).first()
        
        if not asset:
            return jsonify({'status': 'error', 'message': 'Asset not found'}), 404
        
        return jsonify({
            'status': 'success',
            'asset': {
                'id': asset.id,
                'ip': asset.ip,
                'hostname': asset.hostname,
                'os': asset.os,
                'type': asset.type,
                'cloud_provider': asset.cloud_provider,
                'services': [{
                    'id': service.id,
                    'port': service.port,
                    'protocol': service.protocol,
                    'name': service.name,
                    'version': service.version
                } for service in asset.services],
                'vulnerabilities': [{
                    'id': vuln.id,
                    'cve_id': vuln.cve_id,
                    'cvss_score': vuln.cvss_score,
                    'description': vuln.description,
                    'exploit_available': vuln.exploit_available
                } for vuln in asset.vulnerabilities]
            }
        })
    except Exception as e:
        logger.error(f"Error retrieving asset {asset_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        session.close()

@api.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerabilities with optional filtering"""
    session = Session()
    min_cvss = request.args.get('min_cvss', type=float)
    has_exploit = request.args.get('has_exploit', type=int)
    
    try:
        query = session.query(Vulnerability).join(Asset)
        
        if min_cvss is not None:
            query = query.filter(Vulnerability.cvss_score >= min_cvss)
            
        if has_exploit is not None:
            query = query.filter(Vulnerability.exploit_available == bool(has_exploit))
            
        vulns = query.all()
        
        return jsonify({
            'status': 'success',
            'count': len(vulns),
            'vulnerabilities': [{
                'id': vuln.id,
                'cve_id': vuln.cve_id,
                'cvss_score': vuln.cvss_score,
                'description': vuln.description[:150] + '...' if len(vuln.description) > 150 else vuln.description,
                'exploit_available': vuln.exploit_available,
                'asset': {
                    'id': vuln.asset.id,
                    'ip': vuln.asset.ip,
                    'hostname': vuln.asset.hostname
                }
            } for vuln in vulns]
        })
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        session.close()

@api.route('/recommendations', methods=['GET'])
def get_recommendations():
    """Get security recommendations"""
    try:
        business_context = request.args.get('business_context', 'standard')
        recommendations = generate_recommendations(business_context=business_context)
        
        return jsonify({
            'status': 'success',
            'count': len(recommendations),
            'recommendations': recommendations
        })
    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/compliance', methods=['GET'])
def get_compliance():
    """Get compliance report"""
    try:
        framework = request.args.get('framework', 'PCI-DSS')
        compliance_report = generate_compliance_report(framework=framework)
        
        return jsonify({
            'status': 'success',
            'compliance': compliance_report
        })
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/assets/<int:asset_id>/isolate', methods=['POST'])
def isolate_asset_endpoint(asset_id):
    """Isolate an asset from the network"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'API-initiated isolation')
        
        result = isolate_asset(asset_id, reason=reason)
        
        if result.get('success'):
            return jsonify({'status': 'success', 'message': result.get('message')})
        else:
            return jsonify({'status': 'error', 'message': result.get('message')}), 400
    except Exception as e:
        logger.error(f"Error isolating asset {asset_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/assets/<int:asset_id>/restore', methods=['POST'])
def restore_asset_endpoint(asset_id):
    """Restore network access for an isolated asset"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'API-initiated restoration')
        
        result = restore_asset(asset_id, reason=reason)
        
        if result.get('success'):
            return jsonify({'status': 'success', 'message': result.get('message')})
        else:
            return jsonify({'status': 'error', 'message': result.get('message')}), 400
    except Exception as e:
        logger.error(f"Error restoring asset {asset_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    session = Session()
    
    try:
        asset_count = session.query(Asset).count()
        vuln_count = session.query(Vulnerability).count()
        high_risk_count = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 7.0).count()
        
        # Calculate average CVSS score
        result = session.query(func.avg(Vulnerability.cvss_score)).first()
        avg_cvss = round(result[0], 2) if result[0] is not None else 0
        
        return jsonify({
            'status': 'success',
            'stats': {
                'asset_count': asset_count,
                'vulnerability_count': vuln_count,
                'high_risk_count': high_risk_count,
                'average_cvss': avg_cvss
            }
        })
    except Exception as e:
        logger.error(f"Error retrieving stats: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        session.close()