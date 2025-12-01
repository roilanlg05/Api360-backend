import requests
from pydantic import EmailStr
from config.settings import Settings

settings = Settings()
print("server:", settings.BREVO_KEY)

async def send_email(email: EmailStr, sub: str, html_content: str, confirmation_url, name: str | None = None):
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": settings.BREVO_KEY
    }

    if name:
        recipent = [{"email": email, "name": name}]
    else:
        recipent = [{"email": email}]

    payload = {
        "sender": {
            "name": "Api360",
            "email": "no-reply@api360.app"
        },
        "to": recipent,
        "subject": sub,
        "htmlContent": html_content,
        "textContent": f"Confirm your account at: {confirmation_url}"
    }

    response = requests.post(
    url="https://api.brevo.com/v3/smtp/email",
    headers=headers,
    json=payload
    )

    print(f"Ya se envio")
    print(f"Response: {response.text}")
    return response.status_code == 201

# Template in English
def get_confirmation_email_template(confirmation_url: str) -> str:
    """
    Genera el HTML para el email de confirmación de cuenta
    
    Args:
        confirmation_url: URL con el token para verificar el email
        
    Returns:
        str: HTML del email
    """
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirm Your Email</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 40px 20px;
                text-align: center;
            }}
            .header h1 {{
                color: #ffffff;
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .content {{
                padding: 40px 30px;
                color: #333333;
                line-height: 1.6;
            }}
            .content h2 {{
                color: #667eea;
                font-size: 24px;
                margin-top: 0;
                margin-bottom: 20px;
            }}
            .content p {{
                margin: 15px 0;
                font-size: 16px;
            }}
            .button-container {{
                text-align: center;
                margin: 35px 0;
            }}
            .confirm-button {{
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #ffffff;
                text-decoration: none;
                padding: 15px 40px;
                border-radius: 6px;
                font-size: 16px;
                font-weight: 600;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                transition: transform 0.2s ease;
            }}
            .confirm-button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
            }}
            .features {{
                background-color: #f8f9fa;
                padding: 25px;
                border-radius: 6px;
                margin: 25px 0;
            }}
            .features h3 {{
                color: #667eea;
                font-size: 18px;
                margin-top: 0;
                margin-bottom: 15px;
            }}
            .features ul {{
                list-style: none;
                padding: 0;
                margin: 0;
            }}
            .features li {{
                padding: 8px 0;
                font-size: 15px;
                color: #495057;
            }}
            .features li:before {{
                content: "✓ ";
                color: #28a745;
                font-weight: bold;
                margin-right: 8px;
            }}
            .alternative-link {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 6px;
                margin: 25px 0;
                word-break: break-all;
            }}
            .alternative-link p {{
                margin: 5px 0;
                font-size: 13px;
                color: #6c757d;
            }}
            .alternative-link a {{
                color: #667eea;
                text-decoration: none;
                word-break: break-all;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 30px;
                text-align: center;
                border-top: 1px solid #e9ecef;
            }}
            .footer p {{
                margin: 10px 0;
                font-size: 14px;
                color: #6c757d;
            }}
            .footer a {{
                color: #667eea;
                text-decoration: none;
            }}
            .expiration {{
                color: #dc3545;
                font-weight: 600;
            }}
            @media only screen and (max-width: 600px) {{
                .email-container {{
                    margin: 20px 10px;
                }}
                .content {{
                    padding: 30px 20px;
                }}
                .confirm-button {{
                    padding: 12px 30px;
                    font-size: 14px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <!-- Header -->
            <div class="header">
                <h1>🎉 Welcome to Api360!</h1>
            </div>

            <!-- Content -->
            <div class="content">
                <h2>Confirm Your Email Address</h2>
                <p>Hello and welcome!</p>
                <p>
                    Thank you for creating an account with Api360. We're excited to have you on board! 
                    To get started, please confirm your email address by clicking the button below:
                </p>

                <!-- Confirm Button -->
                <div class="button-container">
                    <a href="{confirmation_url}" class="confirm-button">Confirm My Email</a>
                </div>

                <!-- Features Section -->
                <div class="features">
                    <h3>What you can do with Api360:</h3>
                    <ul>
                        <li>Manage your organization and teams</li>
                        <li>Track trips and locations in real-time</li>
                        <li>Coordinate drivers and crew members</li>
                        <li>Access powerful analytics and reports</li>
                        <li>Secure authentication and data protection</li>
                    </ul>
                </div>

                <!-- Alternative Link -->
                <div class="alternative-link">
                    <p><strong>Button not working?</strong> Copy and paste this link into your browser:</p>
                    <p><a href="{confirmation_url}">{confirmation_url}</a></p>
                </div>

                <p>
                    <strong>Note:</strong> This verification link will <span class="expiration">expire in 24 hours</span>.
                </p>

                <p>
                    If you didn't create an account with Api360, you can safely ignore this email.
                </p>

                <p style="margin-top: 30px;">
                    Best regards,<br>
                    <strong>The Api360 Team</strong>
                </p>
            </div>

            <!-- Footer -->
            <div class="footer">
                <p>
                    This is an automated message from Api360.<br>
                    Please do not reply to this email.
                </p>
                <p>
                    Need help? <a href="https://www.optionstriker.com/support">Contact Support</a>
                </p>
                <p style="margin-top: 20px; font-size: 12px; color: #999;">
                    © 2025 Api360. All rights reserved.<br>
                    <a href="https://www.optionstriker.com/privacy">Privacy Policy</a> | 
                    <a href="https://www.optionstriker.com/terms">Terms of Service</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    """

def get_password_reset_email_template(reset_url: str) -> str:
    """
    Genera el HTML para el email de recuperación de contraseña
    
    Args:
        reset_url: URL con el token para resetear la contraseña
        
    Returns:
        str: HTML del email
    """
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 40px 20px;
                text-align: center;
            }}
            .header h1 {{
                color: #ffffff;
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .content {{
                padding: 40px 30px;
                color: #333333;
                line-height: 1.6;
            }}
            .content h2 {{
                color: #667eea;
                font-size: 24px;
                margin-top: 0;
                margin-bottom: 20px;
            }}
            .content p {{
                margin: 15px 0;
                font-size: 16px;
            }}
            .button-container {{
                text-align: center;
                margin: 35px 0;
            }}
            .reset-button {{
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #ffffff;
                text-decoration: none;
                padding: 15px 40px;
                border-radius: 6px;
                font-size: 16px;
                font-weight: 600;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                transition: transform 0.2s ease;
            }}
            .reset-button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
            }}
            .security-notice {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 25px 0;
                border-radius: 4px;
            }}
            .security-notice p {{
                margin: 5px 0;
                font-size: 14px;
                color: #856404;
            }}
            .alternative-link {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 6px;
                margin: 25px 0;
                word-break: break-all;
            }}
            .alternative-link p {{
                margin: 5px 0;
                font-size: 13px;
                color: #6c757d;
            }}
            .alternative-link a {{
                color: #667eea;
                text-decoration: none;
                word-break: break-all;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 30px;
                text-align: center;
                border-top: 1px solid #e9ecef;
            }}
            .footer p {{
                margin: 10px 0;
                font-size: 14px;
                color: #6c757d;
            }}
            .footer a {{
                color: #667eea;
                text-decoration: none;
            }}
            .expiration {{
                color: #dc3545;
                font-weight: 600;
            }}
            @media only screen and (max-width: 600px) {{
                .email-container {{
                    margin: 20px 10px;
                }}
                .content {{
                    padding: 30px 20px;
                }}
                .reset-button {{
                    padding: 12px 30px;
                    font-size: 14px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <!-- Header -->
            <div class="header">
                <h1>🔐 Api360</h1>
            </div>

            <!-- Content -->
            <div class="content">
                <h2>Reset Your Password</h2>
                <p>Hello,</p>
                <p>
                    We received a request to reset your password for your Api360 account. 
                    If you made this request, click the button below to create a new password:
                </p>

                <!-- Reset Button -->
                <div class="button-container">
                    <a href="{reset_url}" class="reset-button">Reset My Password</a>
                </div>

                <!-- Security Notice -->
                <div class="security-notice">
                    <p><strong>⚠️ Security Notice:</strong></p>
                    <p>
                        This link will <span class="expiration">expire in 30 minutes</span> for security reasons. 
                        After using this link once, it will become invalid.
                    </p>
                </div>

                <!-- Alternative Link -->
                <div class="alternative-link">
                    <p><strong>Button not working?</strong> Copy and paste this link into your browser:</p>
                    <p><a href="{reset_url}">{reset_url}</a></p>
                </div>

                <p>
                    If you didn't request a password reset, please ignore this email. 
                    Your password will remain unchanged, and your account is secure.
                </p>

                <p>
                    If you're concerned about your account's security, please contact our support team immediately.
                </p>

                <p style="margin-top: 30px;">
                    Best regards,<br>
                    <strong>The Api360 Team</strong>
                </p>
            </div>

            <!-- Footer -->
            <div class="footer">
                <p>
                    This is an automated message from Api360.<br>
                    Please do not reply to this email.
                </p>
                <p>
                    Need help? <a href="https://www.optionstriker.com/support">Contact Support</a>
                </p>
                <p style="margin-top: 20px; font-size: 12px; color: #999;">
                    © 2025 Api360. All rights reserved.<br>
                    <a href="https://www.optionstriker.com/privacy">Privacy Policy</a> | 
                    <a href="https://www.optionstriker.com/terms">Terms of Service</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    """


# Example usage
if __name__ == "__main__":
    confirmation_url = "https://api360.app/confirm?token=abc123xyz"
    html_template = get_confirmation_email_template(confirmation_url)
    
    send_email(   
        "roilan.lambert5@gmail.com", 
        "🎉 Confirm Your Api360 Account",
        html_template,
    )