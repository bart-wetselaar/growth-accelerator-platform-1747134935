"""
Main entry point for the Growth Accelerator Staffing Platform
"""

# Import the Flask app instance from staffing_app.py
from staffing_app import app
import logging

# LinkedIn Auth setup
import linkedin_auth
from flask import session, redirect, url_for, jsonify, Blueprint
from flask_login import current_user, login_required

# Register the LinkedIn Auth blueprint
linkedin_bp = linkedin_auth.make_linkedin_blueprint()
app.register_blueprint(linkedin_bp, url_prefix="/auth")

# Add test routes directly to the app
try:
    from api_test import add_test_routes
    from app import csrf
    add_test_routes(app, csrf)
    logging.info("Added test API routes with CSRF exemption")
except ImportError as e:
    logging.warning(f"Test API module not found: {str(e)}")
except Exception as e:
    logging.error(f"Error adding test API routes: {str(e)}")

# Register API blueprints from api modules
from flask_wtf.csrf import CSRFProtect

# Get the already initialized CSRF protection from app.py
from app import csrf

# Import API blueprints
try:
    from api.candidates import candidates_bp
    from api.unified import unified_bp
    from api.docs import docs_bp
    
    # Register API blueprints with appropriate URL prefixes
    if candidates_bp:
        app.register_blueprint(candidates_bp, url_prefix='/api')
        csrf.exempt(candidates_bp)
        logging.info("Registered candidates API blueprint in main.py")
    
    if unified_bp:
        app.register_blueprint(unified_bp, url_prefix='/api')
        csrf.exempt(unified_bp)
        logging.info("Registered unified API blueprint in main.py")
        
    if docs_bp:
        app.register_blueprint(docs_bp, url_prefix='/api')
        csrf.exempt(docs_bp)
        logging.info("Registered API docs blueprint in main.py")
except ImportError as e:
    logging.warning(f"Could not register API blueprints: {str(e)}")
except Exception as e:
    logging.error(f"Error registering API blueprints: {str(e)}")

# Make session permanent
@app.before_request
def make_session_permanent():
    if session:
        session.permanent = True

# Add a test API endpoint that's explicitly exempt from CSRF
@app.route('/api/test', methods=['POST'])
@csrf.exempt
def test_api_endpoint():
    """Test API endpoint that's exempt from CSRF protection."""
    data = request.json or {}
    if 'action' == 'jobs' and data.get('operation') == 'list':
        # Forward to the jobs handler in the unified API
        from api.unified import handle_jobs_action
        return handle_jobs_action(data)
    elif data.get('action') == 'candidates' and data.get('operation') == 'list':
        # Forward to the candidates handler in the unified API
        from api.unified import handle_candidates_action
        return handle_candidates_action(data)
    else:
        # Default: just echo the request for testing
        return jsonify({
            "message": "Test API endpoint working",
            "received_data": data
        })

# Add LinkedIn authentication login/logout routes
@app.route('/login-replit')  # Keeping the URL as is for compatibility
def login_replit():
    """Login with LinkedIn"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('linkedin.login'))

@app.route('/logout-replit')  # Keeping the URL as is for compatibility
def logout_replit():
    """Logout from LinkedIn authentication"""
    # Clear all session data
    session.pop('role', None)
    session.pop('use_real_data', None)
    return redirect(url_for('linkedin.logout'))

# Add a protected route that requires LinkedIn Auth
@app.route('/protected')
@login_required
def protected():
    """This route is protected and requires LinkedIn authentication"""
    return f"""
    <h1>LinkedIn Profile</h1>
    <p>Hello, {current_user.username}! You are logged in with LinkedIn.</p>
    <p>Your user ID is: {current_user.id}</p>
    <p>Your email is: {current_user.email or 'not provided'}</p>
    <p>First Name: {current_user.first_name or 'not provided'}</p>
    <p>Last Name: {current_user.last_name or 'not provided'}</p>
    <p><a href="{url_for('index')}">Go back to home</a></p>
    <p><a href="{url_for('logout_replit')}">Logout</a></p>
    """

# This allows gunicorn to find the app variable
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)