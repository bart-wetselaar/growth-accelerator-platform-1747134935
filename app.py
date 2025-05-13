import os
import logging
import json
import requests
from datetime import datetime

from flask import Flask, session, redirect, url_for, render_template, g, jsonify, request, flash, send_file, send_from_directory, make_response
from flask_caching import Cache
import time
from datetime import datetime, timedelta

# Set up caching configuration
cache = Cache(config={'CACHE_TYPE': 'simple'})
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("application.log"),
    ]
)
logger = logging.getLogger(__name__)

# Helper function for domain/environment detection
def get_deployment_info():
    """
    Get information about the current deployment environment
    Returns a dictionary with deployment details
    """
    # Detect deployment environment
    is_azure = bool(os.environ.get('WEBSITE_HOSTNAME'))
    is_azure_main = os.environ.get('WEBSITE_HOSTNAME') == 'app.growthaccelerator.nl'
    is_azure_custom = 'growthaccelerator.nl' in (os.environ.get('WEBSITE_HOSTNAME') or '')
    
    # Determine domain being used
    if is_azure:
        domain = os.environ.get('WEBSITE_HOSTNAME')
    else:
        replit_domains = os.environ.get('REPLIT_DOMAINS', '')
        domain = replit_domains.split(',')[0] if replit_domains else 'webapp.growthaccelerator.nl'
    
    # Get environment name
    if is_azure_main:
        environment = "Azure (Production)"
    elif is_azure_custom:
        environment = "Azure (Custom Domain)"
    elif is_azure:
        environment = "Azure (Staging)"
    else:
        environment = "Replit"
    
    # Get version
    version = os.environ.get('APP_VERSION', '2.1.0')  # Default version is 2.1.0
    
    # Get build information
    build_info = {
        'date': os.environ.get('BUILD_DATE', datetime.utcnow().isoformat()),
        'commit': os.environ.get('GIT_COMMIT', 'unknown'),
        'branch': os.environ.get('GIT_BRANCH', 'main')
    }
    
    return {
        'is_azure': is_azure,
        'is_azure_main': is_azure_main,
        'is_azure_custom': is_azure_custom,
        'domain': domain,
        'environment': environment,
        'version': version,
        'build_info': build_info
    }

# Create database base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Initialize CSRF protection
csrf = CSRFProtect()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "staffing-api-dev-key")
cache.init_app(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Apply security headers middleware
from middleware import add_security_headers
app = add_security_headers(app)

# Apply CSRF protection to the app
csrf.init_app(app)
# Exempt specific routes from CSRF protection to allow automatic login
csrf.exempt("index")
csrf.exempt("login")

# Register health check endpoints for CI/CD monitoring
from health_endpoints import register_health_endpoints
register_health_endpoints(app)
csrf.exempt("health_check")
csrf.exempt("detailed_health_check")
csrf.exempt("version")
csrf.exempt("set_admin_access")

# Initialize Flask-Login with login requirements
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect to login view
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

from flask_login import login_user, login_required
from flask import g

# Uncomment this if you need to bypass login during development
# @app.before_request
# def auto_login():
#     from models import User
#     # Create a demo user in memory if needed
#     if not hasattr(g, 'auto_user'):
#         # Try to get an existing user or create a temporary one
#         user = User.query.first()
#         if not user:
#             # Create a temporary user object (won't be saved to DB)
#             user = User(id=1, username="demo_user", email="demo@example.com")
#         g.auto_user = user
#     # Log in the user for this request
#     login_user(g.auto_user)

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    try:
        return User.query.get(int(user_id))
    except:
        return None

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Set up static file caching
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year in seconds

# Initialize the app with the database extension
db.init_app(app)

with app.app_context():
    # Make sure to import the models here or their tables won't be created
    import models  # noqa: F401
    db.create_all()

# Register blueprints
from controllers.consultant import consultant_bp
from controllers.job import job_bp
from controllers.application import application_bp
from controllers.onboarding import onboarding_bp
from controllers.backoffice import backoffice_bp
# LinkedIn integration removed per user request
from controllers.linkedin_deprecated import linkedin_bp
from controllers.squarespace import squarespace_bp
# The workable_integration module doesn't export a blueprint
# from controllers.workable_integration import workable_bp
from controllers.squarespace_integration import squarespace_bp as squarespace_integration_bp
from debug import debug_bp

app.register_blueprint(consultant_bp)
app.register_blueprint(job_bp)
app.register_blueprint(application_bp)
# app.register_blueprint(onboarding_bp)  # Removed onboarding functionality
# Add debug logging before registering the backoffice blueprint
app.logger.info(f"Registering backoffice blueprint: {backoffice_bp}")
try:
    app.register_blueprint(backoffice_bp)
    app.logger.info("Backoffice blueprint registered successfully")
except Exception as e:
    app.logger.error(f"Error registering backoffice blueprint: {str(e)}")
    raise
# LinkedIn integration removed per user request, but keep the blueprint for backward compatibility
app.register_blueprint(linkedin_bp)
app.register_blueprint(squarespace_bp)
# Register Workable integration at Growth Accelerator paths
# Workable blueprint no longer exists
# app.register_blueprint(workable_bp, url_prefix='/account')
# Register Squarespace job sync integration
app.register_blueprint(squarespace_integration_bp, url_prefix='/squarespace')
# Register debug blueprint
app.register_blueprint(debug_bp)

# Initialize Azure integration with tenant validation
try:
    from azure import initialize_azure_integration
    initialize_azure_integration(app)
    
    # Add direct Azure routes for testing
    from simple_azure_routes import add_azure_routes
    add_azure_routes(app)
    
    # Add simple test Azure route
    from test_azure_route import add_test_azure_route
    add_test_azure_route(app)
    
    # Add our new simplified Azure tenant validation routes
    try:
        from simple_azure_tenant_test import add_simple_azure_routes
        add_simple_azure_routes(app)
        app.logger.info("Simple Azure tenant validation routes added successfully")
    except Exception as e:
        app.logger.error(f"Error adding simple Azure tenant validation routes: {str(e)}")
    
    app.logger.info("Azure integration initialized successfully")
except Exception as e:
    app.logger.error(f"Error initializing Azure integration: {str(e)}")
    # Don't raise the exception - the app should still work without Azure integration

# Import auto recovery services
from services.auto_recovery import AutoRecovery, CircuitBreakerOpenException
from services.service_recovery import (
    recover_workable_service,
    recover_linkedin_service,
    recover_squarespace_service,
    recover_wavebox_service,
    recover_database_connection
)

# Initialize auto recovery service
auto_recovery = AutoRecovery(app)

# Register recovery actions
auto_recovery.register_recovery_action("workable", recover_workable_service)
auto_recovery.register_recovery_action("linkedin", recover_linkedin_service)
auto_recovery.register_recovery_action("squarespace", recover_squarespace_service)
auto_recovery.register_recovery_action("wavebox", recover_wavebox_service)
auto_recovery.register_recovery_action("database", recover_database_connection)

# Create circuit breakers for external services
workable_circuit = auto_recovery.create_circuit_breaker(
    "workable", 
    failure_threshold=3,
    recovery_timeout=30,
    exception_types=[requests.RequestException, ValueError, KeyError, json.JSONDecodeError]
)

linkedin_circuit = auto_recovery.create_circuit_breaker(
    "linkedin", 
    failure_threshold=3,
    recovery_timeout=60
)

squarespace_circuit = auto_recovery.create_circuit_breaker(
    "squarespace", 
    failure_threshold=3,
    recovery_timeout=30
)

wavebox_circuit = auto_recovery.create_circuit_breaker(
    "wavebox", 
    failure_threshold=3,
    recovery_timeout=30
)

# Domain redirection middleware removed as requested

# Error handlers - Now using AutoRecovery
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify(error=str(e)), e.code
    
    if isinstance(e, CircuitBreakerOpenException):
        # Special handling for circuit breaker exceptions
        service_name = str(e).split("for ")[1].split(" ")[0] if "for " in str(e) else "an external"
        logger.warning(f"Circuit breaker open for {service_name} service: {str(e)}")
        
        return jsonify({
            "error": f"The {service_name} service is temporarily unavailable",
            "message": "We're experiencing some technical difficulties. Please try again in a few moments."
        }), 503
    
    # Log the error
    logger.exception("Unhandled exception: %s", str(e))
    
    # Let the auto recovery service handle it
    return auto_recovery.handle_internal_error(e)

# Custom static file handler with enhanced caching support
@app.route('/static/<path:filename>')
def cached_static(filename):
    """Serve static files with proper cache headers"""
    import os
    import hashlib
    
    # Get the full path to the requested file
    file_path = os.path.join(app.static_folder, filename)
    
    # If file doesn't exist, return 404
    if not os.path.isfile(file_path):
        return app.send_static_file(filename)  # Let Flask handle the 404
    
    # Generate ETag based on file modification time and size for better caching
    file_stat = os.stat(file_path)
    etag = hashlib.md5(f"{file_stat.st_mtime}-{file_stat.st_size}".encode()).hexdigest()
    
    # Check If-None-Match header for conditional serving
    if request.headers.get('If-None-Match') == etag:
        return '', 304  # Not Modified
    
    # Prepare response
    response = make_response(send_from_directory('static', filename))
    
    # Set appropriate content type for faster parsing
    if filename.endswith('.css'):
        response.headers['Content-Type'] = 'text/css; charset=utf-8'
        cache_timeout = 2592000  # 30 days for CSS which might change more frequently
    elif filename.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        cache_timeout = 15552000  # 180 days for JS files
    elif filename.endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico')):
        # Long cache for images
        cache_timeout = 31536000  # 1 year for images
    else:
        cache_timeout = 31536000  # 1 year default for static assets
    
    # Add cache control headers with immutability for better performance
    if filename.endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf')):
        # Mark these resources as immutable for browser optimization
        response.headers['Cache-Control'] = f'public, max-age={cache_timeout}, immutable'
    else:
        response.headers['Cache-Control'] = f'public, max-age={cache_timeout}'
    
    # Set Expires header
    response.headers['Expires'] = datetime.now() + timedelta(seconds=cache_timeout)
    
    # Set ETag header
    response.headers['ETag'] = etag
    
    # Enable compression for text-based assets
    if filename.endswith(('.html', '.css', '.js', '.json', '.xml', '.txt', '.svg')):
        vary = response.headers.get('Vary', '')
        if 'Accept-Encoding' not in vary:
            response.headers['Vary'] = f"{vary}, Accept-Encoding" if vary else "Accept-Encoding"
    
    return response

# Handle onboarding routes with 410 Gone
@app.route('/onboarding', defaults={'path': ''})
@app.route('/onboarding/<path:path>')
def handle_onboarding_gone(path):
    """Return 410 Gone for all onboarding routes"""
    return jsonify({
        "error": "Onboarding functionality has been removed",
        "message": "The onboarding functionality is no longer available as it has been moved to Compliance Factory/Cootje."
    }), 410

# Routes
@app.route('/')
def index():
    """Root route"""
    # Domain redirection removed as requested
    current_host = request.host if request else "unknown"
    app.logger.info(f"Serving index page on host: {current_host}")
    
    # Both domains now display identical content without redirection
    return render_template('staffing_app/landing.html')

@app.route('/customer')
def customer_redirect():
    return redirect(url_for('customer_portal'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    # If user is already logged in, redirect to dashboard
    from flask_login import current_user, login_user
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("Login route accessed")
    
    if current_user.is_authenticated:
        logger.info("User already authenticated, redirecting to dashboard")
        return redirect(url_for('dashboard'))
    
    from forms import LoginForm
    form = LoginForm()
    
    # Handle authentication for POST requests
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember_me.data
        
        logger.info(f"Login attempt for user: {username}")
        
        from models import User
        user = User.query.filter_by(username=username).first()
        
        if user:
            logger.info(f"User found in database: {user.id}, {user.username}")
            password_check = user.check_password(password)
            logger.info(f"Password check result: {password_check}")
            
            if password_check:
                logger.info(f"Login successful for: {username}")
                login_user(user, remember=remember)
                next_page = request.args.get('next', url_for('dashboard'))
                
                # Ensure the next page URL is safe
                if not next_page.startswith('/'):
                    next_page = url_for('dashboard')
                    
                flash('Login successful!', 'success')
                return redirect(next_page)
        else:
            logger.warning(f"User not found: {username}")
        
        flash('Invalid username or password', 'danger')
    else:
        if request.method == 'POST':
            logger.warning(f"Form validation failed: {form.errors}")
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    # If user is already logged in, redirect to dashboard
    from flask_login import current_user
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("Register route accessed")
    
    if current_user.is_authenticated:
        logger.info("User already authenticated, redirecting to dashboard")
        return redirect(url_for('dashboard'))
    
    from forms import RegistrationForm
    form = RegistrationForm()
    
    if form.validate_on_submit():
        logger.info(f"Registration form validated for: {form.username.data}, {form.email.data}")
        
        try:
            from models import User
            # Create new user
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            
            # Log the user details (without the password)
            logger.info(f"Created new user object: {user.username}, {user.email}")
            
            db.session.add(user)
            db.session.commit()
            logger.info(f"User {user.username} saved to database with ID: {user.id}")
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user: {str(e)}")
            flash(f'Error creating account: {str(e)}', 'danger')
    else:
        if request.method == 'POST':
            logger.warning(f"Form validation failed: {form.errors}")
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    """Handle user logout and show feedback form"""
    from flask_login import current_user, logout_user
    if current_user.is_authenticated:
        logout_user()
        flash('You have been successfully logged out', 'success')
        # Show the dedicated logout page with feedback form
        return render_template('staffing_app/logout.html')
    # If not authenticated, just go to login
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset request"""
    # If user is already logged in, redirect to dashboard
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    from forms import ResetRequestForm
    form = ResetRequestForm()
    
    if form.validate_on_submit():
        from models import User
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Generate a reset token
            token = user.generate_reset_token()
            db.session.commit()
            
            # In a real-world scenario, you would send an email here
            # For now, we'll just redirect to the reset page with the token
            flash('Password reset link generated. In a production environment, we would email you this link.', 'info')
            return redirect(url_for('reset_password', token=token, email=form.email.data))
        else:
            # Security best practice: Don't reveal whether an email exists
            flash('If that email address is in our system, a password reset link has been sent.', 'info')
            
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset"""
    # If user is already logged in, redirect to dashboard
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Get email from query parameter
    email = request.args.get('email', '')
    
    # Verify the token is valid
    from models import User
    user = User.query.filter_by(email=email).first() if email else None
    
    if not token or not user or not user.verify_reset_token(token):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    from forms import ResetPasswordForm
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.clear_reset_token()
        db.session.commit()
        flash('Your password has been reset. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', form=form)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    from flask_login import current_user
    return render_template('profile.html', user=current_user)

@app.route('/api/info')
@cache.cached(timeout=300)  # Cache this view for 5 minutes
def api_info():
    """Provide API access information"""
    from models import ApiLog, Consultant, Job, Application, Placement
    
    # Use lazy loading to optimize performance and reduce unnecessary loads
    consultant_count = db.session.query(Consultant.id).count()
    job_count = db.session.query(Job.id).count()
    application_count = db.session.query(Application.id).count()
    placement_count = db.session.query(Placement.id).count()
    
@app.route('/debug/routes')
def debug_routes():
    """Debug endpoint to list all routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return jsonify(routes)
    
    # Create a log entry for the request
    log_entry = ApiLog(
        service="api",
        endpoint="/api/info",
        method="GET",
        request_data="API info request",
        response_data="API info returned",
        status_code=200
    )
    db.session.add(log_entry)
    db.session.commit()
    
    # Show API information
    api_info = {
        "api_name": "Growth Accelerator Staffing API",
        "version": "1.0",
        "description": "API for Growth Accelerator staffing operations",
        "endpoints": {
            "/api": "Main unified API endpoint for all operations",
            "/api/account": "Account API endpoint (same as /api)",
            "/api/docs": "API documentation"
        },
        "stats": {
            "consultants": consultant_count,
            "jobs": job_count,
            "applications": application_count,
            "placements": placement_count
        }
    }
    
    return jsonify(api_info)

@app.route('/customer-portal')
def customer_portal():
    """Dashboard at growthaccelerator.nl/customer-portal"""
    from models import Consultant, Job, Application, Placement
    
    # Get recent consultants and jobs for display
    consultants = Consultant.query.order_by(Consultant.created_at.desc()).limit(5).all()
    jobs = Job.query.order_by(Job.created_at.desc()).limit(5).all()
    
    # Get application and placement stats
    total_applications = Application.query.count()
    active_placements = Placement.query.filter_by(status='active').count()
    
    # Get counts for the statistics display
    consultant_count = Consultant.query.count() 
    job_count = Job.query.count()
    
    # Get integration settings for display
    squarespace_api_key = os.environ.get("SQUARESPACE_API_KEY")
    squarespace_job_collection_id = os.environ.get("SQUARESPACE_JOB_COLLECTION_ID")
    
    # Check which integrations are configured
    squarespace_configured = bool(squarespace_api_key) and bool(squarespace_job_collection_id)
    
    return render_template('dashboard.html', 
                          consultants=consultants,
                          jobs=jobs,
                          total_applications=total_applications,
                          active_placements=active_placements,
                          consultant_count=consultant_count,
                          job_count=job_count,
                          squarespace_configured=squarespace_configured,
                          squarespace_job_collection_id=squarespace_job_collection_id)

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view"""
    # Redirect to unified dashboard as the central integration hub
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("Dashboard accessed, redirecting to unified dashboard")
    return redirect('/unified-dashboard/')


@app.route('/account')
def ga_dashboard():
    """Main Growth Accelerator API view at growthacceleratorstaffing.nl/account"""
    # Redirect to Wavebox unified dashboard as the central integration hub
    return redirect('/unified-dashboard/')


# Main route for the API documentation
@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/account/docs')
def account_api_docs():
    return render_template('account_api_docs.html')

# Single Unified API Endpoint for All Operations
@app.route('/api', methods=['GET', 'POST'])
def unified_api():
    """Single unified API endpoint for all operations"""
    # Handle GET requests with a simple API overview and stats
    if request.method == 'GET':
        from models import Consultant, Job, Application, Placement
        
        # Count some basic stats for display
        consultant_count = Consultant.query.count()
        job_count = Job.query.count()
        application_count = Application.query.count()
        placement_count = Placement.query.count()
        
        stats = {
            "api_name": "Growth Accelerator Unified API",
            "version": "1.0",
            "description": "Single unified API endpoint for all operations",
            "documentation_url": url_for('account_api_docs', _external=True),
            "stats": {
                "consultants": consultant_count,
                "jobs": job_count,
                "applications": application_count,
                "placements": placement_count
            }
        }
        
        return jsonify(stats)
    
    # Handle POST requests for API operations
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    action = data.get('action')
    resource = data.get('resource')
    
    if not action or not resource:
        return jsonify({"error": "Action and resource are required"}), 400
    
    # Route to the appropriate handler based on the resource and action
    if resource == 'consultants':
        if action == 'list':
            return api_consultants_list(data)
        elif action == 'get':
            consultant_id = data.get('consultant_id')
            if not consultant_id:
                return jsonify({"error": "consultant_id is required"}), 400
            return api_consultant_detail_info(consultant_id)
        elif action == 'create':
            return api_consultants_create(data)
        elif action == 'update':
            consultant_id = data.get('consultant_id')
            if not consultant_id:
                return jsonify({"error": "consultant_id is required"}), 400
            return api_consultant_update(consultant_id, data)
    
    elif resource == 'matching':
        if action == 'find_matches':
            return api_matching_find(data)
        elif action == 'create_match':
            return api_matching_create(data)
    
    elif resource == 'placements':
        if action == 'list':
            return api_placements_list(data)
        elif action == 'get':
            placement_id = data.get('placement_id')
            if not placement_id:
                return jsonify({"error": "placement_id is required"}), 400
            return api_placement_detail_info(placement_id)
        elif action == 'create':
            return api_placements_create(data)
        elif action == 'update':
            placement_id = data.get('placement_id')
            if not placement_id:
                return jsonify({"error": "placement_id is required"}), 400
            return api_placement_update(placement_id, data)
    
    elif resource == 'onboarding':
        # Onboarding functionality has been deprecated
        return jsonify({"error": "Onboarding functionality has been removed from this API"}), 410
    
    elif resource == 'applications':
        if action == 'list':
            return api_applications_list(data)
            
    elif resource == 'squarespace':
        # Import Squarespace handlers
        from api.squarespace_handlers import (
            api_squarespace_list_jobs,
            api_squarespace_get_job,
            api_squarespace_sync_job,
            api_squarespace_sync_all
        )
        
        if action == 'list_jobs':
            return api_squarespace_list_jobs(data)
        elif action == 'get_job':
            job_id = data.get('job_id')
            if not job_id:
                return jsonify({"error": "job_id is required"}), 400
            return api_squarespace_get_job(job_id)
        elif action == 'sync_job':
            job_id = data.get('job_id')
            if not job_id:
                return jsonify({"error": "job_id is required"}), 400
            return api_squarespace_sync_job(job_id)
        elif action == 'sync_all':
            return api_squarespace_sync_all(data)
    
    # If we get here, the resource/action combination is not supported
    return jsonify({"error": f"Unsupported resource/action: {resource}/{action}"}), 400

# Account API endpoint for backward compatibility
@app.route('/api/account', methods=['GET', 'POST'])
def api_account_integration():
    """Account API endpoint that redirects to the unified API endpoint"""
    return unified_api()

# Documentation pages for API usage
@app.route('/api/docs', methods=['GET'])
def api_documentation():
    """Documentation for the unified API"""
    return render_template('account_api_docs.html')

# Helper functions for Unified API

def api_consultants_list(data):
    """List consultants with optional filtering"""
    from models import Consultant, ConsultantSkill, Skill
    
    # Build query with filters
    query = Consultant.query
    
    if data.get('status'):
        query = query.filter_by(status=data.get('status'))
        
    if data.get('skill_id'):
        query = query.join(Consultant.skills).filter_by(skill_id=data.get('skill_id'))
    
    # Pagination
    page = int(data.get('page', 1))
    per_page = int(data.get('per_page', 20))
    
    consultants = query.paginate(page=page, per_page=per_page)
    
    # Format response
    result = {
        'consultants': [
            {
                'id': c.id,
                'first_name': c.first_name,
                'last_name': c.last_name,
                'email': c.email,
                'status': c.status,
                'hourly_rate': c.hourly_rate,
                'skills': [{'id': s.skill_id, 'name': s.skill.name} for s in c.skills]
            } for c in consultants.items
        ],
        'page': consultants.page,
        'per_page': consultants.per_page,
        'total': consultants.total
    }
    
    return jsonify(result)

def api_consultants_create(data):
    """Create a new consultant"""
    from models import Consultant, Skill, ConsultantSkill, db
    
    try:
        consultant = Consultant(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            phone=data.get('phone'),
            status='new',
            hourly_rate=data.get('hourly_rate')
        )
        
        # Add skills if provided
        if 'skills' in data and data['skills']:
            for skill_data in data['skills']:
                # Check if skill exists, create if not
                skill_name = skill_data.get('name')
                skill = Skill.query.filter_by(name=skill_name).first()
                
                if not skill:
                    skill = Skill(name=skill_name, category=skill_data.get('category', 'General'))
                    db.session.add(skill)
                    db.session.flush()
                
                # Add the skill to the consultant
                consultant_skill = ConsultantSkill(
                    skill_id=skill.id,
                    level=skill_data.get('level', 3),
                    years_experience=skill_data.get('years_experience', 1)
                )
                consultant.skills.append(consultant_skill)
        
        db.session.add(consultant)
        db.session.commit()
        
        return jsonify({
            'id': consultant.id,
            'message': 'Consultant created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_consultant_detail_info(consultant_id):
    """Get detailed consultant information"""
    from models import Consultant
    
    consultant = Consultant.query.get_or_404(consultant_id)
    
    result = {
        'id': consultant.id,
        'first_name': consultant.first_name,
        'last_name': consultant.last_name,
        'email': consultant.email,
        'phone': consultant.phone,
        'status': consultant.status,
        'hourly_rate': consultant.hourly_rate,
        'linkedin_profile': consultant.linkedin_profile,
        'workable_id': consultant.workable_id,
        'resume_url': consultant.resume_url,
        'skills': [
            {
                'id': skill.skill_id,
                'name': skill.skill.name,
                'level': skill.level,
                'years_experience': skill.years_experience
            } for skill in consultant.skills
        ]
    }
    
    return jsonify(result)

def api_consultant_update(consultant_id, data):
    """Update consultant information"""
    from models import Consultant, db
    
    consultant = Consultant.query.get_or_404(consultant_id)
    
    try:
        if 'first_name' in data:
            consultant.first_name = data['first_name']
        if 'last_name' in data:
            consultant.last_name = data['last_name']
        if 'email' in data:
            consultant.email = data['email']
        if 'phone' in data:
            consultant.phone = data['phone']
        if 'status' in data:
            consultant.status = data['status']
        if 'hourly_rate' in data:
            consultant.hourly_rate = data['hourly_rate']
        if 'linkedin_profile' in data:
            consultant.linkedin_profile = data['linkedin_profile']
        if 'resume_url' in data:
            consultant.resume_url = data['resume_url']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Consultant updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_matching_find(data):
    """Find potential matches for a job"""
    from models import Job, Consultant, ConsultantSkill
    
    job_id = data.get('job_id')
    
    if not job_id:
        return jsonify({'error': 'job_id is required'}), 400
    
    job = Job.query.get_or_404(job_id)
    
    # Find consultants with matching skills
    required_skills = [js.skill_id for js in job.required_skills if js.is_required]
    
    if not required_skills:
        # If no required skills, return all available consultants
        consultants = Consultant.query.filter_by(status='active').all()
    else:
        # Find consultants who have the required skills
        consultants = Consultant.query.join(Consultant.skills).filter(
            Consultant.status == 'active',
            ConsultantSkill.skill_id.in_(required_skills)
        ).group_by(Consultant.id).having(
            db.func.count(ConsultantSkill.id) >= len(required_skills)
        ).all()
    
    # Format response
    result = {
        'job': {
            'id': job.id,
            'title': job.title,
            'client': job.client.name,
            'required_skills': [
                {
                    'id': skill.skill_id,
                    'name': skill.skill.name
                } for skill in job.required_skills if skill.is_required
            ]
        },
        'potential_matches': [
            {
                'consultant_id': c.id,
                'name': f"{c.first_name} {c.last_name}",
                'hourly_rate': c.hourly_rate,
                'matching_skills': [
                    {
                        'id': s.skill_id,
                        'name': s.skill.name,
                        'level': s.level,
                        'years_experience': s.years_experience
                    } for s in c.skills if s.skill_id in required_skills
                ]
            } for c in consultants
        ]
    }
    
    return jsonify(result)

def api_matching_create(data):
    """Create a match (application)"""
    from models import Application, ApplicationStatus, db
    
    if not data.get('consultant_id') or not data.get('job_id'):
        return jsonify({'error': 'consultant_id and job_id are required'}), 400
    
    try:
        # Check if already exists
        existing = Application.query.filter_by(
            consultant_id=data['consultant_id'],
            job_id=data['job_id']
        ).first()
        
        if existing:
            return jsonify({'error': 'Match already exists', 'application_id': existing.id}), 400
        
        # Create the application
        application = Application(
            consultant_id=data['consultant_id'],
            job_id=data['job_id'],
            status=ApplicationStatus.NEW,
            notes=data.get('notes', '')
        )
        
        db.session.add(application)
        db.session.commit()
        
        return jsonify({
            'application_id': application.id,
            'message': 'Match created successfully',
            'status': application.status.value
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_placements_list(data):
    """List placements with optional filtering"""
    from models import Placement, Application, Job
    
    query = Placement.query
    
    # Apply filters if provided
    if data.get('status'):
        query = query.filter_by(status=data.get('status'))
        
    if data.get('consultant_id'):
        query = query.join(Placement.application).filter(Application.consultant_id == data.get('consultant_id'))
    
    if data.get('client_id'):
        query = query.join(Placement.application).join(Application.job).filter(Job.client_id == data.get('client_id'))
    
    # Pagination
    page = int(data.get('page', 1))
    per_page = int(data.get('per_page', 20))
    
    placements = query.paginate(page=page, per_page=per_page)
    
    # Format response
    result = {
        'placements': [
            {
                'id': p.id,
                'application_id': p.application_id,
                'consultant': {
                    'id': p.application.consultant_id,
                    'name': f"{p.application.consultant.first_name} {p.application.consultant.last_name}"
                },
                'job': {
                    'id': p.application.job_id,
                    'title': p.application.job.title
                },
                'client': {
                    'id': p.application.job.client_id,
                    'name': p.application.job.client.name
                },
                'start_date': p.start_date.isoformat() if p.start_date else None,
                'end_date': p.end_date.isoformat() if p.end_date else None,
                'hourly_rate': p.hourly_rate,
                'client_bill_rate': p.client_bill_rate,
                'status': p.status,
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            } for p in placements.items
        ],
        'page': placements.page,
        'per_page': placements.per_page,
        'total': placements.total
    }
    
    return jsonify(result)

def api_placements_create(data):
    """Create a new placement"""
    from models import Placement, Application, db
    from datetime import datetime
    
    if not data.get('application_id'):
        return jsonify({'error': 'application_id is required'}), 400
    
    try:
        # Check if application exists
        application = Application.query.get(data['application_id'])
        if not application:
            return jsonify({'error': f"Application with ID {data['application_id']} not found"}), 404
        
        # Check if placement already exists for this application
        existing = Placement.query.filter_by(application_id=data['application_id']).first()
        if existing:
            return jsonify({'error': 'Placement already exists for this application', 'placement_id': existing.id}), 400
        
        # Create the placement
        placement = Placement(
            application_id=data['application_id'],
            start_date=datetime.strptime(data['start_date'], '%Y-%m-%d').date() if data.get('start_date') else None,
            end_date=datetime.strptime(data['end_date'], '%Y-%m-%d').date() if data.get('end_date') else None,
            hourly_rate=data.get('hourly_rate'),
            client_bill_rate=data.get('client_bill_rate'),
            status='pending'
        )
        
        db.session.add(placement)
        db.session.commit()
        
        return jsonify({
            'placement_id': placement.id,
            'message': 'Placement created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_placement_detail_info(placement_id):
    """Get detailed placement information"""
    from models import Placement
    
    placement = Placement.query.get_or_404(placement_id)
    
    result = {
        'id': placement.id,
        'application_id': placement.application_id,
        'consultant': {
            'id': placement.application.consultant_id,
            'name': f"{placement.application.consultant.first_name} {placement.application.consultant.last_name}"
        },
        'job': {
            'id': placement.application.job_id,
            'title': placement.application.job.title
        },
        'client': {
            'id': placement.application.job.client_id,
            'name': placement.application.job.client.name
        },
        'start_date': placement.start_date.isoformat() if placement.start_date else None,
        'end_date': placement.end_date.isoformat() if placement.end_date else None,
        'hourly_rate': placement.hourly_rate,
        'client_bill_rate': placement.client_bill_rate,
        'status': placement.status,
        'created_at': placement.created_at.isoformat() if placement.created_at else None,
        'updated_at': placement.updated_at.isoformat() if placement.updated_at else None
    }
    
    return jsonify(result)

def api_placement_update(placement_id, data):
    """Update placement information"""
    from models import Placement, db
    from datetime import datetime
    
    placement = Placement.query.get_or_404(placement_id)
    
    try:
        if 'start_date' in data:
            placement.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
        if 'end_date' in data:
            placement.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date() if data['end_date'] else None
        if 'hourly_rate' in data:
            placement.hourly_rate = data['hourly_rate']
        if 'client_bill_rate' in data:
            placement.client_bill_rate = data['client_bill_rate']
        if 'status' in data:
            placement.status = data['status']
            
        db.session.commit()
        
        return jsonify({
            'message': 'Placement updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_applications_list(data):
    """List applications with optional filtering"""
    from models import Application, ApplicationStatus
    
    query = Application.query
    
    # Apply filters if provided
    if data.get('status'):
        try:
            enum_status = ApplicationStatus[data.get('status').upper()]
            query = query.filter_by(status=enum_status)
        except (KeyError, ValueError):
            # Invalid status, ignore filter
            pass
            
    if data.get('consultant_id'):
        query = query.filter_by(consultant_id=data.get('consultant_id'))
    
    if data.get('job_id'):
        query = query.filter_by(job_id=data.get('job_id'))
    
    # Pagination
    page = int(data.get('page', 1))
    per_page = int(data.get('per_page', 20))
    
    applications = query.paginate(page=page, per_page=per_page)
    
    # Format response
    result = {
        'applications': [
            {
                'id': app.id,
                'consultant': {
                    'id': app.consultant.id,
                    'name': f"{app.consultant.first_name} {app.consultant.last_name}"
                },
                'job': {
                    'id': app.job.id,
                    'title': app.job.title
                },
                'status': app.status.value,
                'applied_at': app.applied_at.isoformat(),
                'last_status_change': app.last_status_change.isoformat(),
                'workable_application_id': app.workable_application_id
            } for app in applications.items
        ],
        'page': applications.page,
        'per_page': applications.per_page,
        'total': applications.total
    }
    
    return jsonify(result)

def api_onboarding_list(data):
    """List onboarding data with optional filtering"""
    from models import OnboardingData, Consultant
    
    query = OnboardingData.query
    
    # Apply filters
    if data.get('consultant_id'):
        query = query.filter_by(consultant_id=data.get('consultant_id'))
        
    if data.get('onboarding_complete') is not None:
        query = query.filter_by(onboarding_complete=data.get('onboarding_complete'))
        
    # Pagination
    page = int(data.get('page', 1))
    per_page = int(data.get('per_page', 20))
    
    onboarding_records = query.paginate(page=page, per_page=per_page)
    
    # Format response
    result = {
        'onboarding_records': [
            {
                'id': o.id,
                'consultant_id': o.consultant_id,
                'consultant_name': f"{o.consultant.first_name} {o.consultant.last_name}",
                'onboarding_complete': o.onboarding_complete,
                'contract_signed': o.contract_signed,
                'nda_signed': o.nda_signed,
                'background_check_complete': o.background_check_complete,
                'created_at': o.created_at.isoformat() if o.created_at else None,
                'updated_at': o.updated_at.isoformat() if o.updated_at else None
            } for o in onboarding_records.items
        ],
        'page': onboarding_records.page,
        'per_page': onboarding_records.per_page,
        'total': onboarding_records.total
    }
    
    return jsonify(result)

def api_onboarding_create(data):
    """Create a new onboarding record"""
    from models import OnboardingData, Consultant, db
    
    if not data.get('consultant_id'):
        return jsonify({'error': 'consultant_id is required'}), 400
    
    try:
        # Check if consultant exists
        consultant = Consultant.query.get(data['consultant_id'])
        if not consultant:
            return jsonify({'error': f"Consultant with ID {data['consultant_id']} not found"}), 404
            
        # Check if record already exists
        existing = OnboardingData.query.filter_by(consultant_id=data['consultant_id']).first()
        if existing:
            return jsonify({'error': 'Onboarding record already exists for this consultant', 'onboarding_id': existing.id}), 400
            
        # Create the onboarding record
        onboarding = OnboardingData(
            consultant_id=data['consultant_id'],
            tax_id=data.get('tax_id'),
            address=data.get('address'),
            city=data.get('city'),
            state=data.get('state'),
            zip_code=data.get('zip_code'),
            country=data.get('country'),
            bank_name=data.get('bank_name'),
            bank_account_number=data.get('bank_account_number'),
            routing_number=data.get('routing_number'),
            emergency_contact_name=data.get('emergency_contact_name'),
            emergency_contact_phone=data.get('emergency_contact_phone'),
            contract_signed=data.get('contract_signed', False),
            nda_signed=data.get('nda_signed', False),
            background_check_complete=data.get('background_check_complete', False),
            onboarding_complete=data.get('onboarding_complete', False)
        )
        
        db.session.add(onboarding)
        db.session.commit()
        
        return jsonify({
            'onboarding_id': onboarding.id,
            'message': 'Onboarding record created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

def api_onboarding_update(onboarding_id, data):
    """Update onboarding information"""
    from models import OnboardingData, db
    
    onboarding = OnboardingData.query.get_or_404(onboarding_id)
    
    try:
        if 'tax_id' in data:
            onboarding.tax_id = data['tax_id']
        if 'address' in data:
            onboarding.address = data['address']
        if 'city' in data:
            onboarding.city = data['city']
        if 'state' in data:
            onboarding.state = data['state']
        if 'zip_code' in data:
            onboarding.zip_code = data['zip_code']
        if 'country' in data:
            onboarding.country = data['country']
        if 'bank_name' in data:
            onboarding.bank_name = data['bank_name']
        if 'bank_account_number' in data:
            onboarding.bank_account_number = data['bank_account_number']
        if 'routing_number' in data:
            onboarding.routing_number = data['routing_number']
        if 'emergency_contact_name' in data:
            onboarding.emergency_contact_name = data['emergency_contact_name']
        if 'emergency_contact_phone' in data:
            onboarding.emergency_contact_phone = data['emergency_contact_phone']
        if 'contract_signed' in data:
            onboarding.contract_signed = data['contract_signed']
        if 'nda_signed' in data:
            onboarding.nda_signed = data['nda_signed']
        if 'background_check_complete' in data:
            onboarding.background_check_complete = data['background_check_complete']
        if 'onboarding_complete' in data:
            onboarding.onboarding_complete = data['onboarding_complete']
            
        db.session.commit()
        
        return jsonify({
            'message': 'Onboarding record updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# API Endpoints for Wavebox Integration
@app.route('/api/v1/consultants', methods=['GET', 'POST'])
def api_consultants():
    """API endpoint for consultant management"""
    from models import Consultant, db, ConsultantSkill, Skill
    
    if request.method == 'GET':
        # Fetch consultants with optional filtering
        query = Consultant.query
        
        # Apply filters if provided
        if request.args.get('status'):
            query = query.filter_by(status=request.args.get('status'))
            
        if request.args.get('skill'):
            query = query.join(Consultant.skills).filter_by(skill_id=request.args.get('skill'))
        
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        consultants = query.paginate(page=page, per_page=per_page)
        
        # Format response
        result = {
            'consultants': [
                {
                    'id': c.id,
                    'first_name': c.first_name,
                    'last_name': c.last_name,
                    'email': c.email,
                    'status': c.status,
                    'hourly_rate': c.hourly_rate,
                    'skills': [{'id': s.skill_id, 'name': s.skill.name} for s in c.skills]
                } for c in consultants.items
            ],
            'page': consultants.page,
            'per_page': consultants.per_page,
            'total': consultants.total
        }
        
        return jsonify(result)
    
    elif request.method == 'POST':
        # Create a new consultant
        data = request.json
        
        try:
            consultant = Consultant(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                phone=data.get('phone'),
                status='new',
                hourly_rate=data.get('hourly_rate')
            )
            
            # Add skills if provided
            if 'skills' in data and data['skills']:
                for skill_data in data['skills']:
                    # Check if skill exists, create if not
                    skill_name = skill_data.get('name')
                    skill = Skill.query.filter_by(name=skill_name).first()
                    
                    if not skill:
                        skill = Skill(name=skill_name, category=skill_data.get('category', 'General'))
                        db.session.add(skill)
                        db.session.flush()
                    
                    # Add the skill to the consultant
                    consultant_skill = ConsultantSkill(
                        skill_id=skill.id,
                        level=skill_data.get('level', 3),
                        years_experience=skill_data.get('years_experience', 1)
                    )
                    consultant.skills.append(consultant_skill)
            
            db.session.add(consultant)
            db.session.commit()
            
            return jsonify({
                'id': consultant.id,
                'message': 'Consultant created successfully'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

@app.route('/api/v1/consultants/<int:consultant_id>', methods=['GET', 'PUT', 'DELETE'])
def api_consultant_detail(consultant_id):
    """API endpoint for managing a specific consultant"""
    from models import Consultant, db
    
    consultant = Consultant.query.get_or_404(consultant_id)
    
    if request.method == 'GET':
        # Return consultant details
        result = {
            'id': consultant.id,
            'first_name': consultant.first_name,
            'last_name': consultant.last_name,
            'email': consultant.email,
            'phone': consultant.phone,
            'status': consultant.status,
            'hourly_rate': consultant.hourly_rate,
            'linkedin_profile': consultant.linkedin_profile,
            'workable_id': consultant.workable_id,
            'wavebox_id': consultant.wavebox_id,
            'resume_url': consultant.resume_url,
            'skills': [
                {
                    'id': skill.skill_id,
                    'name': skill.skill.name,
                    'level': skill.level,
                    'years_experience': skill.years_experience
                } for skill in consultant.skills
            ]
        }
        
        return jsonify(result)
    
    elif request.method == 'PUT':
        # Update consultant
        data = request.json
        
        try:
            if 'first_name' in data:
                consultant.first_name = data['first_name']
            if 'last_name' in data:
                consultant.last_name = data['last_name']
            if 'email' in data:
                consultant.email = data['email']
            if 'phone' in data:
                consultant.phone = data['phone']
            if 'status' in data:
                consultant.status = data['status']
            if 'hourly_rate' in data:
                consultant.hourly_rate = data['hourly_rate']
            if 'linkedin_profile' in data:
                consultant.linkedin_profile = data['linkedin_profile']
            if 'resume_url' in data:
                consultant.resume_url = data['resume_url']
            
            db.session.commit()
            
            return jsonify({
                'message': 'Consultant updated successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400
    
    elif request.method == 'DELETE':
        try:
            db.session.delete(consultant)
            db.session.commit()
            
            return jsonify({
                'message': 'Consultant deleted successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

@app.route('/api/v1/matching', methods=['GET', 'POST'])
def api_matching():
    """API endpoint for job-consultant matching"""
    from models import Consultant, Job, Application, ApplicationStatus, db, ConsultantSkill
    
    if request.method == 'GET':
        # Get possible matches based on skills
        job_id = request.args.get('job_id')
        
        if not job_id:
            return jsonify({'error': 'job_id parameter is required'}), 400
        
        job = Job.query.get_or_404(job_id)
        
        # Find consultants with matching skills
        required_skills = [js.skill_id for js in job.required_skills if js.is_required]
        
        if not required_skills:
            # If no required skills, return all available consultants
            consultants = Consultant.query.filter_by(status='active').all()
        else:
            # Find consultants who have the required skills
            consultants = Consultant.query.join(Consultant.skills).filter(
                Consultant.status == 'active',
                ConsultantSkill.skill_id.in_(required_skills)
            ).group_by(Consultant.id).having(
                db.func.count(ConsultantSkill.id) >= len(required_skills)
            ).all()
        
        # Format response
        result = {
            'job': {
                'id': job.id,
                'title': job.title,
                'client': job.client.name,
                'required_skills': [
                    {
                        'id': skill.skill_id,
                        'name': skill.skill.name
                    } for skill in job.required_skills if skill.is_required
                ]
            },
            'potential_matches': [
                {
                    'consultant_id': c.id,
                    'name': f"{c.first_name} {c.last_name}",
                    'hourly_rate': c.hourly_rate,
                    'matching_skills': [
                        {
                            'id': s.skill_id,
                            'name': s.skill.name,
                            'level': s.level,
                            'years_experience': s.years_experience
                        } for s in c.skills if s.skill_id in required_skills
                    ]
                } for c in consultants
            ]
        }
        
        return jsonify(result)
    
    elif request.method == 'POST':
        # Create a match (application)
        data = request.json
        
        if not data.get('consultant_id') or not data.get('job_id'):
            return jsonify({'error': 'consultant_id and job_id are required'}), 400
        
        try:
            # Check if already exists
            existing = Application.query.filter_by(
                consultant_id=data['consultant_id'],
                job_id=data['job_id']
            ).first()
            
            if existing:
                return jsonify({'error': 'Match already exists', 'application_id': existing.id}), 400
            
            # Create the application
            application = Application(
                consultant_id=data['consultant_id'],
                job_id=data['job_id'],
                status=ApplicationStatus.NEW,
                notes=data.get('notes', '')
            )
            
            db.session.add(application)
            db.session.commit()
            
            return jsonify({
                'application_id': application.id,
                'message': 'Match created successfully',
                'status': application.status.value
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

@app.route('/api/v1/placements', methods=['GET', 'POST'])
def api_placements():
    """API endpoint for placement management (Hire & Contracting)"""
    from models import Placement, db, Application, Consultant, Job
    
    if request.method == 'GET':
        # Get all placements with optional filtering
        query = Placement.query
        
        # Apply filters if provided
        if request.args.get('status'):
            query = query.filter_by(status=request.args.get('status'))
            
        if request.args.get('consultant_id'):
            query = query.join(Placement.application).filter(Application.consultant_id == request.args.get('consultant_id'))
        
        if request.args.get('client_id'):
            query = query.join(Placement.application).join(Application.job).filter(Job.client_id == request.args.get('client_id'))
        
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        placements = query.paginate(page=page, per_page=per_page)
        
        # Format response
        result = {
            'placements': [
                {
                    'id': p.id,
                    'application_id': p.application_id,
                    'consultant': {
                        'id': p.application.consultant_id,
                        'name': f"{p.application.consultant.first_name} {p.application.consultant.last_name}"
                    },
                    'job': {
                        'id': p.application.job_id,
                        'title': p.application.job.title
                    },
                    'client': {
                        'id': p.application.job.client_id,
                        'name': p.application.job.client.name
                    },
                    'start_date': p.start_date.isoformat() if p.start_date else None,
                    'end_date': p.end_date.isoformat() if p.end_date else None,
                    'hourly_rate': p.hourly_rate,
                    'client_bill_rate': p.client_bill_rate,
                    'status': p.status,
                    'wavebox_id': p.wavebox_id,
                    'created_at': p.created_at.isoformat() if p.created_at else None,
                    'updated_at': p.updated_at.isoformat() if p.updated_at else None
                } for p in placements.items
            ],
            'page': placements.page,
            'per_page': placements.per_page,
            'total': placements.total
        }
        
        return jsonify(result)
    
    elif request.method == 'POST':
        # Create a new placement
        data = request.json
        
        if not data.get('application_id'):
            return jsonify({'error': 'application_id is required'}), 400
        
        try:
            # Check if application exists
            application = Application.query.get(data['application_id'])
            if not application:
                return jsonify({'error': f"Application with ID {data['application_id']} not found"}), 404
            
            # Check if placement already exists for this application
            existing = Placement.query.filter_by(application_id=data['application_id']).first()
            if existing:
                return jsonify({'error': 'Placement already exists for this application', 'placement_id': existing.id}), 400
            
            # Create the placement
            placement = Placement(
                application_id=data['application_id'],
                start_date=datetime.strptime(data['start_date'], '%Y-%m-%d').date() if data.get('start_date') else None,
                end_date=datetime.strptime(data['end_date'], '%Y-%m-%d').date() if data.get('end_date') else None,
                hourly_rate=data.get('hourly_rate'),
                client_bill_rate=data.get('client_bill_rate'),
                status='pending'
            )
            
            db.session.add(placement)
            db.session.commit()
            
            return jsonify({
                'placement_id': placement.id,
                'message': 'Placement created successfully',
                'status': placement.status
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

@app.route('/api/v1/placements/<int:placement_id>', methods=['GET', 'PUT'])
def api_placement_detail(placement_id):
    """API endpoint for managing a specific placement"""
    from models import Placement, db
    
    placement = Placement.query.get_or_404(placement_id)
    
    if request.method == 'GET':
        # Return placement details
        result = {
            'id': placement.id,
            'application_id': placement.application_id,
            'consultant': {
                'id': placement.application.consultant_id,
                'name': f"{placement.application.consultant.first_name} {placement.application.consultant.last_name}"
            },
            'job': {
                'id': placement.application.job_id,
                'title': placement.application.job.title
            },
            'client': {
                'id': placement.application.job.client_id,
                'name': placement.application.job.client.name
            },
            'start_date': placement.start_date.isoformat() if placement.start_date else None,
            'end_date': placement.end_date.isoformat() if placement.end_date else None,
            'hourly_rate': placement.hourly_rate,
            'client_bill_rate': placement.client_bill_rate,
            'status': placement.status,
            'wavebox_id': placement.wavebox_id,
            'created_at': placement.created_at.isoformat() if placement.created_at else None,
            'updated_at': placement.updated_at.isoformat() if placement.updated_at else None
        }
        
        return jsonify(result)
    
    elif request.method == 'PUT':
        # Update placement
        data = request.json
        
        try:
            if 'status' in data:
                placement.status = data['status']
            if 'start_date' in data:
                placement.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date() if data['start_date'] else None
            if 'end_date' in data:
                placement.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date() if data['end_date'] else None
            if 'hourly_rate' in data:
                placement.hourly_rate = data['hourly_rate']
            if 'client_bill_rate' in data:
                placement.client_bill_rate = data['client_bill_rate']
            if 'wavebox_id' in data:
                placement.wavebox_id = data['wavebox_id']
            
            db.session.commit()
            
            return jsonify({
                'message': 'Placement updated successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

@app.route('/api/v1/onboarding', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_onboarding():
    """API endpoint for consultant onboarding"""
    # Onboarding API endpoint has been removed
    return jsonify({
        "error": "Onboarding functionality has been removed",
        "message": "The onboarding functionality is no longer available as it has been moved to Compliance Factory/Cootje."
    }), 410

# Onboarding functionality has been removed
# All onboarding-related code has been commented out as it's handled by Compliance Factory/Cootje



# Make some objects available to all templates
@app.context_processor
def inject_global_vars():
    from datetime import datetime
    
    # Get deployment info from helper function
    deployment_info = get_deployment_info()
    
    # Ensure same data appears regardless of domain
    return {
        'app_name': 'Growth Accelerator Staffing',
        'now': datetime.now(),
        'version': deployment_info['version'],
        'app_domain': 'growthaccelerator.nl',
        'is_azure': deployment_info['is_azure'],
        'is_replit': not deployment_info['is_azure'],
        'deployment_environment': deployment_info['environment'],
        'current_domain': deployment_info['domain']
    }

# Temporary wireframe download routes - will be removed after use
@app.route('/wireframe_downloads')
# Removed login_required to allow direct access
def wireframe_downloads():
    """Temporary page with wireframe download links"""
    return render_template('wireframe_downloads.html')

@app.route('/download_wireframe_svg')
# Removed login_required to allow direct access
def download_wireframe_svg():
    """Temporary route to download the wireframe SVG"""
    return send_file('static/img/wireframe_app.svg', 
                 mimetype='image/svg+xml',
                 download_name='Growth_Accelerator_Wireframe.svg',
                 as_attachment=True)

@app.route('/download_wireframe_pdf')
# Removed login_required to allow direct access
def download_wireframe_pdf():
    """Temporary route to download the wireframe as PDF"""
    return send_file('static/img/wireframe_app.svg', 
                 mimetype='application/pdf',
                 download_name='Growth_Accelerator_Wireframe.pdf',
                 as_attachment=True)

# Backup management routes
@app.route('/backups')
@login_required
def backups():
    """Show backup files available for download"""
    import os
    from datetime import datetime
    
    backups_dir = './backups'
    backup_files = []
    
    # Ensure the directory exists
    if os.path.exists(backups_dir):
        for filename in os.listdir(backups_dir):
            if filename.endswith('.tar.gz'):
                file_path = os.path.join(backups_dir, filename)
                size_mb = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
                mtime = os.path.getmtime(file_path)
                date_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                backup_files.append({
                    'filename': filename,
                    'size_mb': f"{size_mb:.2f}",
                    'date': date_str
                })
    
    # Sort backups by date (newest first)
    backup_files = sorted(backup_files, key=lambda x: x['filename'], reverse=True)
    
    return render_template('backup_download.html', backups=backup_files)

@app.route('/backups/download/<filename>')
@login_required
def download_backup(filename):
    """Download a backup file"""
    import os
    from flask import send_from_directory, abort
    
    # Security check - only allow .tar.gz files
    if not filename.endswith('.tar.gz'):
        abort(404)
    
    # Security check - ensure the file exists in backups directory
    backups_dir = './backups'
    file_path = os.path.join(backups_dir, filename)
    
    if not os.path.exists(file_path):
        abort(404)
    
    # Log the download
    logger.info(f"Backup file download: {filename}")
    
    return send_from_directory(backups_dir, filename, as_attachment=True)

# Direct health check endpoints for CI/CD and monitoring
@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Basic health check endpoint that returns 200 OK if the app is running."""
    host = request.host if request else "unknown"
    deployment_info = get_deployment_info()
    
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'version': deployment_info['version'],
        'host': host,
        'domain': deployment_info['domain'],
        'deployment': deployment_info['environment']
    }), 200

@app.route('/api/health/detailed', methods=['GET'])
def api_detailed_health_check():
    """Detailed health check with database connection test."""
    from sqlalchemy import text
    start_time = time.time()
    checks = {
        'app': {
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat()
        }
    }
    
    # Check database connection
    try:
        db.session.execute(text('SELECT 1'))
        db.session.commit()
        checks['database'] = {
            'status': 'ok',
            'message': 'Database connection successful'
        }
    except Exception as e:
        checks['database'] = {
            'status': 'error',
            'message': str(e)
        }
    
    # Determine overall status
    overall_status = 'ok'
    for check in checks.values():
        if check.get('status') == 'error':
            overall_status = 'error'
            break
    
    response = {
        'status': overall_status,
        'checks': checks,
        'duration_ms': int((time.time() - start_time) * 1000)
    }
    
    status_code = 200 if overall_status == 'ok' else 500
    return jsonify(response), status_code

@app.route('/api/version', methods=['GET'])
def api_version():
    """Return the application version."""
    version_info = {
        'version': os.environ.get('APP_VERSION', 'development'),
        'commit': os.environ.get('GIT_COMMIT', 'unknown'),
        'build_date': os.environ.get('BUILD_DATE', datetime.utcnow().isoformat())
    }
    return jsonify(version_info), 200

# Azure test endpoints - using multiple patterns to ensure they work across domains
@app.route('/api/azure-test', methods=['GET'])
def azure_test_direct():
    """Direct test endpoint for Azure integration."""
    return jsonify({
        'success': True,
        'message': 'Azure direct test endpoint is working via /api/azure-test',
        'tenant_id': os.environ.get('AZURE_TENANT_ID', '27eafe03-bbf2-4d8d-acd6-a65a6bfecf7b'),
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/api/health/azure', methods=['GET'])
def azure_health_test():
    """Health check endpoint for Azure integration."""
    return jsonify({
        'success': True,
        'message': 'Azure health check endpoint is working via /api/health/azure',
        'tenant_id': os.environ.get('AZURE_TENANT_ID', '27eafe03-bbf2-4d8d-acd6-a65a6bfecf7b'),
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/api/azure/direct-test', methods=['GET'])
def azure_direct_test_with_prefix():
    """Direct test endpoint with azure prefix for Azure integration."""
    return jsonify({
        'success': True,
        'message': 'Azure test endpoint is working via /api/azure/direct-test',
        'tenant_id': os.environ.get('AZURE_TENANT_ID', '27eafe03-bbf2-4d8d-acd6-a65a6bfecf7b'),
        'timestamp': datetime.utcnow().isoformat()
    }), 200

# Register API blueprints
try:
    from api import candidates_bp, unified_bp, docs_bp
    
    # Debug info about blueprint objects
    logger.info(f"API blueprints: candidates_bp={candidates_bp}, unified_bp={unified_bp}, docs_bp={docs_bp}")
    
    if candidates_bp:
        app.register_blueprint(candidates_bp, url_prefix='/api')
        csrf.exempt(candidates_bp)
        logger.info("Registered candidates API blueprint")
    else:
        logger.warning("candidates_bp is None, not registering")
    
    if unified_bp:
        app.register_blueprint(unified_bp, url_prefix='/api')
        csrf.exempt(unified_bp)
        logger.info("Registered unified API blueprint")
    else:
        logger.warning("unified_bp is None, not registering")
        
    if docs_bp:
        app.register_blueprint(docs_bp, url_prefix='/api')
        csrf.exempt(docs_bp)
        logger.info("Registered API docs blueprint")
    else:
        logger.warning("docs_bp is None, not registering")
except ImportError as e:
    logger.warning(f"Could not register API blueprints: {str(e)}")
except Exception as e:
    logger.error(f"Error registering API blueprints: {str(e)}")

# Register test API routes directly (not as a blueprint)
try:
    from api_test import add_test_routes
    add_test_routes(app, csrf)
    logger.info("Added test API routes successfully")
except Exception as e:
    logger.error(f"Error adding test API routes: {str(e)}")

# Register Azure deployment blueprint
try:
    from azure_deploy import register_azure_deploy
    register_azure_deploy(app)
    logger.info("Registered Azure deployment interface")
except Exception as e:
    logger.error(f"Failed to register Azure deployment interface: {str(e)}")

# Simple direct Azure deployment route (fallback)
@app.route('/direct-azure-deploy')
def direct_azure_deploy_dashboard():
    """Direct Azure deployment dashboard (fallback)"""
    return render_template('deploy_azure.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
