from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, create_engine, UniqueConstraint, Float, LargeBinary, Index
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

engine = create_engine('sqlite:///myfinance.db')
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'

    user_id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    email_iv = Column(String, nullable=False)
    phone = Column(String, nullable=False, unique=True)
    phone_iv = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    full_name_iv = Column(String, nullable=False)
    mfa_secret = Column(String, nullable=True)
    mfa_secret_iv = Column(String, nullable=True)
    locked = Column(Boolean, default=False)

    portfolios = relationship("Portfolio", back_populates="user", foreign_keys="Portfolio.user_id")

class Portfolio(Base):
    __tablename__ = 'portfolios'

    portfolio_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    portfolio_name = Column(String, nullable=False)
    portfolio_name_iv = Column(String, nullable=False)
    total_value = Column(String, nullable=False)
    total_value_iv = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # Relationships
    user = relationship("User", back_populates="portfolios", foreign_keys=[user_id])
    source_transactions = relationship("Transaction", back_populates="source_portfolio",
                                       foreign_keys="Transaction.source_portfolio_id")
    destination_transactions = relationship("Transaction", back_populates="destination_portfolio",
                                            foreign_keys="Transaction.destination_portfolio_id")

class Transaction(Base):
    __tablename__ = 'transactions'

    transaction_id = Column(Integer, primary_key=True)
    amount = Column(String, nullable=False)
    amount_iv = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    description = Column(String)
    description_iv = Column(String)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    user = relationship("User", foreign_keys=[user_id])
    source_portfolio_id = Column(Integer, ForeignKey('portfolios.portfolio_id'), nullable=True)
    destination_portfolio_id = Column(Integer, ForeignKey('portfolios.portfolio_id'), nullable=True)
    initiated_by = Column(String, nullable=False, default='client')
    source_portfolio = relationship("Portfolio", back_populates="source_transactions",
                                    foreign_keys=[source_portfolio_id])
    destination_portfolio = relationship("Portfolio", back_populates="destination_transactions",
                                         foreign_keys=[destination_portfolio_id])
    nonce = Column(String, nullable=False)
    hmac_signature = Column(String, nullable=False)

class UserSymmetricKeys(Base):
    __tablename__ = 'user_symmetric_keys'

    key_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    encrypted_dek = Column(String, nullable=False)
    dek_iv = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    active = Column(Boolean, default=True)
    last_rotated = Column(DateTime, nullable=True)

    user = relationship("User")

class LoginAttempts(Base):
    __tablename__ = 'login_attempts'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    success = Column(Boolean, nullable=False)

    user = relationship("User", foreign_keys=[user_id])

class Logs(Base):
    __tablename__ = 'audit_trails'

    audit_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=True)
    action = Column(String, nullable=False)
    description = Column(String, nullable=False)
    description_iv = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False)

    user = relationship("User", foreign_keys=[user_id])

class UserAsymmetricKeys(Base):
    __tablename__ = 'user_asymmetric_keys'

    key_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    private_key_encrypted = Column(LargeBinary, nullable=False)
    private_key_iv = Column(String, nullable=False)
    key_version = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    user = relationship("User")
    sent_messages = relationship("Message", foreign_keys="[Message.sender_key_id]", back_populates="sender_key")
    received_messages = relationship("Message", foreign_keys="[Message.recipient_key_id]", back_populates="recipient_key")


class Message(Base):
    __tablename__ = 'messages'

    message_id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    sender_key_id = Column(Integer, ForeignKey('user_asymmetric_keys.key_id'), nullable=False)
    recipient_key_id = Column(Integer, ForeignKey('user_asymmetric_keys.key_id'), nullable=False)
    encrypted_message = Column(String, nullable=False)
    message_iv = Column(String, nullable=False)
    encrypted_symmetric_key = Column(String, nullable=False)
    signature = Column(String, nullable=False)
    nonce = Column(String, nullable=False)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False)

    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
    sender_key = relationship("UserAsymmetricKeys", foreign_keys=[sender_key_id], back_populates="sent_messages")
    recipient_key = relationship("UserAsymmetricKeys", foreign_keys=[recipient_key_id], back_populates="received_messages")

Base.metadata.create_all(engine)
session.close()