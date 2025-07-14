# routers/transaction.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from uuid import uuid4
from datetime import datetime
from app.models.constant import IST
import json
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.schemas.transaction import TransactionInput, FraudPredictionResponse
from app.models.transaction import Transaction
from app.models.profile import Profile
from app.models.user import User
from app.database import get_db
from app.services.fraud_service import run_fraud_pipeline
from app.services.device_service import calculate_derived_columns
from app.routers.auth import get_current_user
from app.config import settings

router = APIRouter(prefix="/transaction", tags=["Transaction"])
templates = Jinja2Templates(directory="app/templates")

# Store OTP temporarily (in production, use Redis or database)
otp_store = {}

@router.post("/", response_model=FraudPredictionResponse)
def create_and_predict_transaction(
    request: Request,
    amount: float = Form(...),
    transaction_type: str = Form(...),
    payment_method: str = Form(...),
    recipient_upi_id: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")

    # Generate timestamp features
    now = datetime.now(IST)
    is_night = now.hour < 6 or now.hour > 22

    # Calculate derived columns internally (device_id from cookie/header, location from IP)
    derived_data = calculate_derived_columns(request)

    # Get last transaction for distance calculation
    last_txn = db.query(Transaction).filter(
        Transaction.user_id == current_user.user_id
    ).order_by(Transaction.created_at.desc()).first()

    last_transaction_location = None
    if last_txn and last_txn.latitude and last_txn.longitude:
        last_transaction_location = {
            'latitude': float(last_txn.latitude),
            'longitude': float(last_txn.longitude)
        }

    # Save transaction
    txn_id = str(uuid4())
    new_txn = Transaction(
        transaction_id=txn_id,
        user_id=current_user.user_id,
        amount=amount,
        transaction_type=transaction_type,
        payment_instrument=payment_method,
        payer_vpa=profile.upi_id,
        beneficiary_vpa=recipient_upi_id,
        initiation_mode=derived_data["initiation_mode"],  # Always "Default"
        device_id=derived_data["device_id"],
        ip_address=derived_data["ip_address"],
        latitude=derived_data["latitude"],
        longitude=derived_data["longitude"],
        country=derived_data["country"],
        city=derived_data["city"],
        day_of_week=now.weekday(),
        hour=now.hour,
        minute=now.minute,
        is_night=is_night,
        created_at=now
    )
    db.add(new_txn)
    db.commit()
    db.refresh(new_txn)

    # Get count of past transactions for the user
    txn_count = db.query(Transaction).filter(Transaction.user_id == current_user.user_id).count()

    # Use model
    result = run_fraud_pipeline(
        new_txn, 
        profile, 
        txn_count=txn_count, 
        last_transaction_location=last_transaction_location,
        db_session=db
    )

    new_txn.is_fraud = bool(result["final_prediction"])
    db.commit()

    # Routing logic based on fraud detection results
    if new_txn.is_fraud:
        # Step-up authentication: Send OTP
        otp = random.randint(100000, 999999)
        otp_store[profile.upi_id] = otp  # Store OTP
        
        # Send OTP via email (assuming user's email is available in profile)
        msg = MIMEMultipart()
        msg['From'] = settings.EMAIL_FROM
        msg['To'] = profile.email
        msg['Subject'] = 'Your OTP Code'
        body = f"Your OTP code is {otp}. It is valid for 10 minutes."
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_FROM, settings.EMAIL_PASSWORD)
            server.send_message(msg)
        
        return {"detail": "Fraud detected. OTP sent to registered email."}
    
    return result

@router.post("/verify_otp")
def verify_otp(
    request: Request,
    otp: int = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    
    # Verify OTP
    stored_otp = otp_store.get(profile.upi_id)
    if not stored_otp or stored_otp != otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # OTP verified, remove from store
    del otp_store[profile.upi_id]

    return {"detail": "OTP verified successfully. Transaction approved."}

@router.delete("/{txn_id}")
def delete_transaction(
    txn_id: str, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    txn = db.query(Transaction).get(txn_id)
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    db.delete(txn)
    db.commit()
    return {"msg": "Transaction deleted"}

@router.post("/process", response_class=HTMLResponse)
async def process_transaction(
    request: Request,
    amount: float = Form(...),
    transaction_type: str = Form(...),
    payment_method: str = Form(...),
    recipient_upi_id: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Process transaction and route based on fraud detection results"""
    try:
        profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
        user = db.query(User).filter(User.user_id == current_user.user_id).first()
        
        if not profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        # Generate timestamp features
        now = datetime.now()
        is_night = now.hour < 6 or now.hour > 22

        # Calculate derived columns
        derived_data = calculate_derived_columns(request)

        # Get last transaction for distance calculation
        last_txn = db.query(Transaction).filter(
            Transaction.user_id == current_user.user_id
        ).order_by(Transaction.created_at.desc()).first()

        last_transaction_location = None
        if last_txn and last_txn.latitude and last_txn.longitude:
            last_transaction_location = {
                'latitude': float(last_txn.latitude),
                'longitude': float(last_txn.longitude)
            }

        # Create transaction object for fraud detection (don't save yet)
        txn_id = str(uuid4())
        temp_txn = Transaction(
            transaction_id=txn_id,
            user_id=current_user.user_id,
            amount=amount,
            transaction_type=transaction_type,
            payment_instrument=payment_method,
            payer_vpa=profile.upi_id,
            beneficiary_vpa=recipient_upi_id,
            initiation_mode=derived_data["initiation_mode"],
            device_id=derived_data["device_id"],
            ip_address=derived_data["ip_address"],
            latitude=derived_data["latitude"],
            longitude=derived_data["longitude"],
            country=derived_data["country"],
            city=derived_data["city"],
            day_of_week=now.weekday(),
            hour=now.hour,
            minute=now.minute,
            is_night=is_night,
            created_at=now
        )

        # Get count of past transactions for the user
        txn_count = db.query(Transaction).filter(Transaction.user_id == current_user.user_id).count()

        # Run fraud detection
        fraud_result = run_fraud_pipeline(
            temp_txn, 
            profile, 
            txn_count=txn_count, 
            last_transaction_location=last_transaction_location,
            db_session=db
        )

        # Prepare transaction data for templates
        transaction_data = {
            "transaction_id": txn_id,
            "amount": amount,
            "transaction_type": transaction_type,
            "payment_method": payment_method,
            "to_account": recipient_upi_id,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "from_account": profile.upi_id
        }

        # Route based on fraud detection result
        # If final_prediction == 1 (fraud detected/is_phishing:true), redirect to step-up auth
        # If final_prediction == 0 (no fraud/is_phishing:false), show transaction success
        if fraud_result["final_prediction"] == 1:  # Fraud detected
            # Store transaction data in session for step-up auth
            transaction_json = json.dumps({
                **transaction_data,
                "temp_txn_data": {
                    "amount": amount,
                    "transaction_type": transaction_type,
                    "payment_method": payment_method,
                    "recipient_upi_id": recipient_upi_id,
                    "derived_data": derived_data,
                    "txn_count": txn_count,
                    "last_transaction_location": last_transaction_location
                }
            })
            
            return templates.TemplateResponse(
                "step_up.html", 
                {
                    "request": request,
                    "user": current_user,
                    "fraud_details": fraud_result,
                    "transaction_data": transaction_json,
                    "user_email": user.email if user else None
                }
            )
        else:  # No fraud detected
            # Save the transaction
            db.add(temp_txn)
            temp_txn.is_fraud = False
            db.commit()
            db.refresh(temp_txn)
            
            return templates.TemplateResponse(
                "transaction_results.html",
                {
                    "request": request,
                    "user": current_user,
                    "transaction_data": transaction_data,
                    "fraud_report": fraud_result
                }
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction processing failed: {str(e)}")

@router.post("/auth/step-up-verify", response_class=HTMLResponse)
async def step_up_verify(
    request: Request,
    action: str = Form(...),
    email: str = Form(None),
    otp: str = Form(None),
    transaction_data: str = Form(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Handle step-up authentication for suspicious transactions"""
    try:
        if action == "send_otp":
            # Generate and send OTP
            otp_code = str(random.randint(100000, 999999))
            otp_store[email] = otp_code
            
            # Send OTP email (simplified - in production use proper email service)
            success = send_otp_email(email, otp_code)
            
            if success:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "otp_sent": True,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "success": "OTP sent successfully to your email!"
                    }
                )
            else:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "error": "Failed to send OTP. Please try again."
                    }
                )
                
        elif action == "verify_otp":
            # Verify OTP and process transaction
            if email in otp_store and otp_store[email] == otp:
                # OTP verified successfully, redirect to identity verified page
                del otp_store[email]  # Remove used OTP
                
                # Redirect to identity verified success page
                return templates.TemplateResponse(
                    "identity_verified.html",
                    {
                        "request": request,
                        "user": current_user
                    }
                )
            else:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "otp_sent": True,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "error": "Invalid OTP. Please try again."
                    }
                )
                
        elif action == "resend_otp":
            # Resend OTP
            otp_code = str(random.randint(100000, 999999))
            otp_store[email] = otp_code
            
            success = send_otp_email(email, otp_code)
            
            return templates.TemplateResponse(
                "step_up.html",
                {
                    "request": request,
                    "user": current_user,
                    "otp_sent": True,
                    "user_email": email,
                    "transaction_data": transaction_data,
                    "success": "OTP resent successfully!" if success else "Failed to resend OTP."
                }
            )
            
    except Exception as e:
        return templates.TemplateResponse(
            "step_up.html",
            {
                "request": request,
                "user": current_user,
                "error": f"An error occurred: {str(e)}"
            }
        )

@router.get("/transactions", response_class=HTMLResponse)
async def view_transactions(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    # Get all transactions for the current user, ordered by most recent first
    transactions = (db.query(Transaction)
                   .filter(Transaction.user_id == user.user_id)
                   .order_by(desc(Transaction.created_at))
                   .all())
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "transactions": transactions
        }
    )

def send_otp_email(email: str, otp: str) -> bool:
    """Send OTP via email"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = settings.SMTP_USERNAME if hasattr(settings, 'SMTP_USERNAME') else "noreply@cipherstorm.com"
        msg['To'] = email
        msg['Subject'] = "CipherStorm - Transaction Verification OTP"
        
        body = f"""
        <html>
            <body>
                <h2 style="color: #00ff99;">CipherStorm - Transaction Verification</h2>
                <p>We detected unusual activity in your transaction. For your security, please verify your identity.</p>
                <h3 style="color: #00ffcc;">Your OTP: <span style="background: #000; padding: 10px; border-radius: 5px;">{otp}</span></h3>
                <p>This OTP is valid for 10 minutes.</p>
                <p>If you didn't attempt this transaction, please contact support immediately.</p>
                <hr>
                <p style="color: #666;">CipherStorm AI-Powered Fraud Detection System</p>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to server and send email
        if hasattr(settings, 'SMTP_SERVER'):
            server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT)
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
            return True
        else:
            # Fallback - just log the OTP for development
            print(f"OTP for {email}: {otp}")
            return True
            
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False