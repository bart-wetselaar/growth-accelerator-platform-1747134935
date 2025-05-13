"""
Direct Azure Deployment Module for Growth Accelerator Platform

This module provides direct Azure deployment functionality integrated with
the Partner client ID for seamless Azure App Service deployment.
"""

import os
import sys
import logging
import subprocess
import tempfile
import json
import time
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, current_app, session

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Azure configuration
AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', '27eafe03-bbf2-4d8d-acd6-a65a6bfecf7b')
AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID', 'c770a5c1-f36e-4819-8e18-2ccbbc187c46')  # Partner Client ID
AZURE_SUBSCRIPTION_ID = os.environ.get('AZURE_SUBSCRIPTION_ID', '6e40e67a-fee6-4737-b308-e4c4ebee9a5c')

# GitHub configuration
GITHUB_REPO_URL = "https://github.com/bart-wetselaar/growth-accelerator-platform-1747134935"
GITHUB_BRANCH = "main"

# Azure resource configuration
RESOURCE_GROUP = "growth-accelerator-rg"
LOCATION = "westeurope"
APP_NAME = "growthacceleratorapp"
APP_SERVICE_PLAN = f"{APP_NAME}-plan"
CUSTOM_DOMAIN = "app.growthaccelerator.nl"

# Create blueprint
direct_deploy_bp = Blueprint('direct_deploy', __name__, url_prefix='/azure/deploy')

# Global deployment state
deployment_status = {
    "in_progress": False,
    "last_deployment": None,
    "logs": [],
    "current_step": "",
    "success": None
}

def add_log(message):
    """Add a log message to the deployment log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    deployment_status["logs"].append(log_entry)
    logger.info(message)

def update_step(step):
    """Update the current deployment step"""
    deployment_status["current_step"] = step
    add_log(f"Step: {step}")

def get_deployment_status():
    """Get the current deployment status"""
    if deployment_status["last_deployment"]:
        last_deployment = deployment_status["last_deployment"].strftime("%Y-%m-%d %H:%M:%S")
    else:
        last_deployment = "Never"

    return {
        "in_progress": deployment_status["in_progress"],
        "last_deployment": last_deployment,
        "logs": deployment_status["logs"],
        "current_step": deployment_status["current_step"],
        "success": deployment_status["success"]
    }

def run_azure_cli_command(command, check=True):
    """Run an Azure CLI command and log the output"""
    add_log(f"Running: az {' '.join(command)}")
    try:
        result = subprocess.run(["az"] + command, 
                               check=check, 
                               capture_output=True, 
                               text=True)
        if result.stdout.strip():
            add_log(f"Output: {result.stdout.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        add_log(f"Error: {e.stderr.strip()}")
        if not check:
            return e
        raise

def azure_login(client_secret):
    """Log in to Azure using service principal"""
    update_step("Logging in to Azure")
    try:
        command = [
            "login", 
            "--service-principal",
            "--username", AZURE_CLIENT_ID,
            "--password", client_secret,
            "--tenant", AZURE_TENANT_ID
        ]
        run_azure_cli_command(command)
        
        # Set subscription
        add_log(f"Setting subscription to: {AZURE_SUBSCRIPTION_ID}")
        run_azure_cli_command(["account", "set", "--subscription", AZURE_SUBSCRIPTION_ID])
        return True
    except Exception as e:
        add_log(f"Error during Azure login: {str(e)}")
        return False

def create_resource_group():
    """Create a resource group if it doesn't exist"""
    update_step("Creating/checking resource group")
    try:
        # Check if resource group exists
        result = run_azure_cli_command(
            ["group", "show", "--name", RESOURCE_GROUP],
            check=False
        )
        
        if result.returncode == 0:
            add_log(f"Resource group {RESOURCE_GROUP} already exists")
        else:
            # Create resource group
            run_azure_cli_command([
                "group", "create", 
                "--name", RESOURCE_GROUP, 
                "--location", LOCATION, 
                "--tags", f"partner-id={AZURE_CLIENT_ID}"
            ])
            add_log(f"Resource group {RESOURCE_GROUP} created successfully")
        return True
    except Exception as e:
        add_log(f"Error creating resource group: {str(e)}")
        return False

def create_app_service_plan():
    """Create an App Service Plan if it doesn't exist"""
    update_step("Creating/checking App Service Plan")
    try:
        # Check if App Service Plan exists
        result = run_azure_cli_command(
            ["appservice", "plan", "show", "--name", APP_SERVICE_PLAN, "--resource-group", RESOURCE_GROUP],
            check=False
        )
        
        if result.returncode == 0:
            add_log(f"App Service Plan {APP_SERVICE_PLAN} already exists")
        else:
            # Create App Service Plan
            run_azure_cli_command([
                "appservice", "plan", "create",
                "--name", APP_SERVICE_PLAN,
                "--resource-group", RESOURCE_GROUP,
                "--location", LOCATION,
                "--sku", "B1",
                "--is-linux",
                "--tags", f"partner-id={AZURE_CLIENT_ID}"
            ])
            add_log(f"App Service Plan {APP_SERVICE_PLAN} created successfully")
        return True
    except Exception as e:
        add_log(f"Error creating App Service Plan: {str(e)}")
        return False

def create_web_app():
    """Create a Web App if it doesn't exist"""
    update_step("Creating/checking Web App")
    try:
        # Check if Web App exists
        result = run_azure_cli_command(
            ["webapp", "show", "--name", APP_NAME, "--resource-group", RESOURCE_GROUP],
            check=False
        )
        
        if result.returncode == 0:
            add_log(f"Web App {APP_NAME} already exists")
        else:
            # Create Web App
            run_azure_cli_command([
                "webapp", "create",
                "--name", APP_NAME,
                "--resource-group", RESOURCE_GROUP,
                "--plan", APP_SERVICE_PLAN,
                "--runtime", "PYTHON:3.11",
                "--tags", f"partner-id={AZURE_CLIENT_ID}"
            ])
            add_log(f"Web App {APP_NAME} created successfully")
        return True
    except Exception as e:
        add_log(f"Error creating Web App: {str(e)}")
        return False

def configure_github_deployment(github_token=None):
    """Configure deployment from GitHub"""
    update_step("Configuring GitHub deployment")
    try:
        command = [
            "webapp", "deployment", "source", "config",
            "--name", APP_NAME,
            "--resource-group", RESOURCE_GROUP,
            "--repo-url", GITHUB_REPO_URL,
            "--branch", GITHUB_BRANCH
        ]
        
        if github_token:
            command.extend(["--git-token", github_token])
            
        run_azure_cli_command(command)
        add_log("GitHub deployment configured successfully")
        return True
    except Exception as e:
        add_log(f"Error configuring GitHub deployment: {str(e)}")
        return False

def setup_monitoring():
    """Set up Application Insights for monitoring"""
    update_step("Setting up Application Insights")
    try:
        run_azure_cli_command([
            "monitor", "app-insights", "component", "create",
            "--app", f"{APP_NAME}-insights",
            "--resource-group", RESOURCE_GROUP,
            "--location", LOCATION,
            "--application-type", "web",
            "--kind", "web"
        ], check=False)  # Don't fail if it already exists
        
        # Get the instrumentation key
        result = run_azure_cli_command([
            "monitor", "app-insights", "component", "show",
            "--app", f"{APP_NAME}-insights",
            "--resource-group", RESOURCE_GROUP,
            "--query", "instrumentationKey",
            "--output", "tsv"
        ])
        
        instrumentation_key = result.stdout.strip()
        return instrumentation_key
    except Exception as e:
        add_log(f"Error setting up monitoring: {str(e)}")
        add_log("Continuing despite monitoring setup failure")
        return None

def configure_app_settings(instrumentation_key=None, secrets=None):
    """Configure application settings"""
    update_step("Configuring application settings")
    try:
        settings = [
            f"AZURE_TENANT_ID={AZURE_TENANT_ID}",
            f"AZURE_CLIENT_ID={AZURE_CLIENT_ID}",
            f"AZURE_SUBSCRIPTION_ID={AZURE_SUBSCRIPTION_ID}",
            f"WEBSITES_PORT=5000",
            f"SCM_DO_BUILD_DURING_DEPLOYMENT=true"
        ]
        
        if instrumentation_key:
            settings.append(f"APPINSIGHTS_INSTRUMENTATIONKEY={instrumentation_key}")
            settings.append(f"ApplicationInsightsAgent_EXTENSION_VERSION=~3")
            
        # Add provided secrets
        if secrets:
            for key, value in secrets.items():
                if value:  # Only add non-empty values
                    settings.append(f"{key}={value}")
        
        run_azure_cli_command([
            "webapp", "config", "appsettings", "set",
            "--name", APP_NAME,
            "--resource-group", RESOURCE_GROUP,
            "--settings"
        ] + settings)
        
        add_log("Application settings configured successfully")
        return True
    except Exception as e:
        add_log(f"Error configuring application settings: {str(e)}")
        return False

def configure_web_app_settings():
    """Configure web app settings"""
    update_step("Configuring web app settings")
    try:
        run_azure_cli_command([
            "webapp", "config", "set",
            "--name", APP_NAME,
            "--resource-group", RESOURCE_GROUP,
            "--always-on", "true",
            "--min-tls-version", "1.2",
            "--http20-enabled", "true",
            "--ftps-state", "Disabled",
            "--health-check-path", "/api/health"
        ])
        
        add_log("Web app settings configured successfully")
        return True
    except Exception as e:
        add_log(f"Error configuring web app settings: {str(e)}")
        return False

def configure_custom_domain():
    """Configure custom domain and SSL"""
    update_step("Configuring custom domain")
    try:
        # Check if domain is already configured
        result = run_azure_cli_command([
            "webapp", "config", "hostname", "list",
            "--webapp-name", APP_NAME,
            "--resource-group", RESOURCE_GROUP,
            "--query", f"[?name=='{CUSTOM_DOMAIN}'].name",
            "--output", "tsv"
        ])
        
        domain_exists = result.stdout.strip()
        
        if not domain_exists:
            add_log(f"Adding custom domain: {CUSTOM_DOMAIN}")
            
            # Add the custom domain
            run_azure_cli_command([
                "webapp", "config", "hostname", "add",
                "--webapp-name", APP_NAME,
                "--resource-group", RESOURCE_GROUP,
                "--hostname", CUSTOM_DOMAIN
            ])
            
            # Create and bind a managed certificate
            add_log(f"Creating managed certificate for {CUSTOM_DOMAIN}")
            run_azure_cli_command([
                "webapp", "config", "ssl", "create",
                "--name", APP_NAME,
                "--resource-group", RESOURCE_GROUP,
                "--hostname", CUSTOM_DOMAIN,
                "--only-enable-https"
            ])
        else:
            add_log(f"Custom domain {CUSTOM_DOMAIN} is already configured")
            
        return True
    except Exception as e:
        add_log(f"Error configuring custom domain: {str(e)}")
        add_log("Custom domain configuration failed, but deployment will continue")
        return False

def trigger_deployment():
    """Trigger deployment"""
    update_step("Triggering deployment")
    try:
        run_azure_cli_command([
            "webapp", "deployment", "source", "sync",
            "--name", APP_NAME,
            "--resource-group", RESOURCE_GROUP
        ])
        
        add_log("Deployment triggered successfully")
        return True
    except Exception as e:
        add_log(f"Error triggering deployment: {str(e)}")
        return False

def verify_deployment():
    """Verify deployment"""
    update_step("Verifying deployment")
    try:
        # Get the web app URL
        result = run_azure_cli_command([
            "webapp", "show",
            "--name", APP_NAME,
            "--resource-group", RESOURCE_GROUP,
            "--query", "defaultHostName",
            "--output", "tsv"
        ])
        
        webapp_url = result.stdout.strip()
        add_log(f"Web app deployed to: https://{webapp_url}")
        add_log(f"Custom domain: https://{CUSTOM_DOMAIN}")
        
        return {
            "default_url": f"https://{webapp_url}",
            "custom_url": f"https://{CUSTOM_DOMAIN}"
        }
    except Exception as e:
        add_log(f"Error verifying deployment: {str(e)}")
        return None

def run_deployment(client_secret, github_token=None, secrets=None):
    """Run the deployment process"""
    deployment_status["in_progress"] = True
    deployment_status["logs"] = []
    deployment_status["current_step"] = ""
    deployment_status["success"] = None
    
    add_log("Starting deployment to Azure")
    
    try:
        # Login to Azure
        if not azure_login(client_secret):
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at Azure login step")
            return False
            
        # Create Azure resources
        if not create_resource_group():
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at resource group creation step")
            return False
            
        if not create_app_service_plan():
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at App Service Plan creation step")
            return False
            
        if not create_web_app():
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at Web App creation step")
            return False
            
        # Configure GitHub deployment
        if not configure_github_deployment(github_token):
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at GitHub deployment configuration step")
            return False
            
        # Set up monitoring
        instrumentation_key = setup_monitoring()
        
        # Configure application settings
        if not configure_app_settings(instrumentation_key, secrets):
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at application settings configuration step")
            return False
            
        # Configure web app settings
        if not configure_web_app_settings():
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at web app settings configuration step")
            return False
            
        # Configure custom domain
        configure_custom_domain()  # Continue even if this fails
        
        # Trigger deployment
        if not trigger_deployment():
            deployment_status["in_progress"] = False
            deployment_status["success"] = False
            add_log("Deployment failed at deployment trigger step")
            return False
            
        # Verify deployment
        urls = verify_deployment()
        
        # Update deployment status
        deployment_status["in_progress"] = False
        deployment_status["last_deployment"] = datetime.now()
        deployment_status["success"] = True
        add_log("Deployment completed successfully")
        
        return urls
    except Exception as e:
        add_log(f"Deployment failed with exception: {str(e)}")
        deployment_status["in_progress"] = False
        deployment_status["success"] = False
        return False

# Routes

@direct_deploy_bp.route('/dashboard')
def deploy_dashboard():
    """Azure direct deployment dashboard"""
    return render_template(
        'azure/deploy_dashboard.html',
        status=get_deployment_status(),
        title="Deploy to Azure",
        repo_url=GITHUB_REPO_URL,
        branch=GITHUB_BRANCH
    )

@direct_deploy_bp.route('/api/status')
def api_status():
    """Get current deployment status"""
    return jsonify(get_deployment_status())

@direct_deploy_bp.route('/api/deploy', methods=['POST'])
def api_deploy():
    """Start deployment process"""
    if deployment_status["in_progress"]:
        return jsonify({
            "success": False,
            "message": "Deployment already in progress"
        }), 409
        
    data = request.json
    client_secret = data.get('client_secret')
    github_token = data.get('github_token')
    secrets = data.get('secrets', {})
    
    if not client_secret:
        return jsonify({
            "success": False,
            "message": "Azure client secret is required"
        }), 400
        
    # Start deployment in a background thread
    import threading
    deployment_thread = threading.Thread(
        target=run_deployment,
        args=(client_secret, github_token, secrets)
    )
    deployment_thread.daemon = True
    deployment_thread.start()
    
    return jsonify({
        "success": True,
        "message": "Deployment started"
    })

def register_azure_direct_deploy(app):
    """Register the Azure direct deployment blueprint with the main app"""
    app.register_blueprint(direct_deploy_bp)
    logger.info("Azure direct deployment blueprint registered")