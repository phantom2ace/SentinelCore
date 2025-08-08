from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Float, Boolean
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    ip = Column(String(15), nullable=False)
    hostname = Column(String(100))
    os = Column(String(50))
    asset_type = Column(String(50))
    cloud_provider = Column(String(20))
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
    asset_id = Column(Integer, ForeignKey('assets.id'))
    asset = relationship('Asset', back_populates='vulnerabilities')

engine = create_engine('sqlite:///sentinel_core.db')
Base.metadata.create_all(engine)