from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Float, Boolean
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    ip = Column(String(15), nullable=False)
    hostname = Column(String(100))
    os = Column(String(50))
    asset_type = Column(String(50))
    cloud_provider = Column(String(20))
    isolated = Column(Boolean, default=False)
    isolation_time = Column(String(50), nullable=True)
    services = relationship('Service', back_populates='asset')
    vulnerabilities = relationship('Vulnerability', back_populates='asset')

class Service(Base):
    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(3))
    name = Column(String(50))
    version = Column(String(100))
    asset_id = Column(Integer, ForeignKey('assets.id'))
    asset = relationship('Asset', back_populates='services')

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20))
    description = Column(String(500))
    cvss_score = Column(Float)
    exploit_available = Column(Boolean)
    remediated = Column(Boolean, default=False)
    auto_remediated = Column(Boolean, default=False)
    remediation_date = Column(String(50), nullable=True)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    asset = relationship('Asset', back_populates='vulnerabilities')

# Create a new class for remediation history
class RemediationHistory(Base):
    __tablename__ = 'remediation_history'
    id = Column(Integer, primary_key=True)
    date = Column(String(50), nullable=False)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    action = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False)  # 'successful', 'failed'
    details = Column(String(500))
    asset = relationship('Asset')

# Create engine and session
engine = create_engine('sqlite:///sentinel_core.db')
Session = sessionmaker(bind=engine)

# Create tables
Base.metadata.create_all(engine)
