#!/bin/bash

# Direct Azure Deployment Script using Partner Client ID
# This script deploys directly to Azure using the Azure CLI

# Set variables
RESOURCE_GROUP="growth-accelerator-rg"
LOCATION="westeurope"
APP_NAME="growthacceleratorapp"
APP_SERVICE_PLAN="${APP_NAME}-plan"
CUSTOM_DOMAIN="app.growthaccelerator.nl"
TENANT_ID="${AZURE_TENANT_ID:-27eafe03-bbf2-4d8d-acd6-a65a6bfecf7b}"
CLIENT_ID="${AZURE_CLIENT_ID:-c770a5c1-f36e-4819-8e18-2ccbbc187c46}"  # Partner Client ID
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-6e40e67a-fee6-4737-b308-e4c4ebee9a5c}"
GITHUB_REPO="https://github.com/bart-wetselaar/growth-accelerator-platform-1747134935"
GITHUB_BRANCH="main"

# Print banner
echo "============================================================="
echo "  Growth Accelerator Platform - Direct Azure Deployment  "
echo "============================================================="
echo "Tenant ID: $TENANT_ID"
echo "Partner Client ID: $CLIENT_ID"
echo "Resource Group: $RESOURCE_GROUP"
echo "GitHub Repository: $GITHUB_REPO"
echo ""

# Check prerequisites
if ! command -v az &> /dev/null; then
    echo "Error: Azure CLI is not installed. Please install Azure CLI first."
    echo "Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if user is already logged in
CURRENT_ACCOUNT=$(az account show --query name -o tsv 2>/dev/null)
if [ -z "$CURRENT_ACCOUNT" ]; then
    echo "You are not logged in to Azure. Please log in first."
    
    # Check if we have client secret for service principal login
    if [ -n "$AZURE_CLIENT_SECRET" ]; then
        echo "Logging in using service principal..."
        az login --service-principal \
            --username "$CLIENT_ID" \
            --password "$AZURE_CLIENT_SECRET" \
            --tenant "$TENANT_ID"
    else
        echo "Please run: az login"
        exit 1
    fi
fi

# Set subscription
echo "Setting subscription: $SUBSCRIPTION_ID"
az account set --subscription "$SUBSCRIPTION_ID"

# Create Resource Group if it doesn't exist
echo "Creating Resource Group if needed..."
az group exists --name "$RESOURCE_GROUP" | grep -q "true" || \
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --tags "partner-id=$CLIENT_ID"

# Create App Service Plan if it doesn't exist
echo "Creating App Service Plan if needed..."
az appservice plan show --name "$APP_SERVICE_PLAN" --resource-group "$RESOURCE_GROUP" &>/dev/null || \
az appservice plan create --name "$APP_SERVICE_PLAN" --resource-group "$RESOURCE_GROUP" \
    --sku B1 --is-linux --location "$LOCATION" --tags "partner-id=$CLIENT_ID"

# Create Web App if it doesn't exist
echo "Creating Web App if needed..."
az webapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null || \
az webapp create --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --plan "$APP_SERVICE_PLAN" --runtime "PYTHON:3.11" --tags "partner-id=$CLIENT_ID"

# Configure deployment from GitHub
echo "Configuring GitHub deployment..."
if [ -n "$GITHUB_TOKEN" ]; then
    az webapp deployment source config --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
        --repo-url "$GITHUB_REPO" --branch "$GITHUB_BRANCH" --git-token "$GITHUB_TOKEN"
else
    echo "GITHUB_TOKEN not set. Configuring deployment without token (public repository only)."
    az webapp deployment source config --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
        --repo-url "$GITHUB_REPO" --branch "$GITHUB_BRANCH"
fi

# Create Application Insights
echo "Setting up Application Insights..."
az monitor app-insights component create --app "${APP_NAME}-insights" \
    --resource-group "$RESOURCE_GROUP" --location "$LOCATION" \
    --application-type web --kind web || true

# Get the instrumentation key
INSTRUMENTATION_KEY=$(az monitor app-insights component show \
    --app "${APP_NAME}-insights" --resource-group "$RESOURCE_GROUP" \
    --query instrumentationKey -o tsv)

# Configure application settings
echo "Configuring application settings..."
az webapp config appsettings set --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --settings \
        AZURE_TENANT_ID="$TENANT_ID" \
        AZURE_CLIENT_ID="$CLIENT_ID" \
        AZURE_SUBSCRIPTION_ID="$SUBSCRIPTION_ID" \
        WORKABLE_API_KEY="${WORKABLE_API_KEY:-}" \
        LINKEDIN_CLIENT_ID="${LINKEDIN_CLIENT_ID:-}" \
        LINKEDIN_CLIENT_SECRET="${LINKEDIN_CLIENT_SECRET:-}" \
        SQUARESPACE_API_KEY="${SQUARESPACE_API_KEY:-}" \
        WEBSITES_PORT="5000" \
        SCM_DO_BUILD_DURING_DEPLOYMENT="true" \
        APPINSIGHTS_INSTRUMENTATIONKEY="$INSTRUMENTATION_KEY" \
        ApplicationInsightsAgent_EXTENSION_VERSION="~3"

# Configure web app settings
echo "Configuring web app settings..."
az webapp config set --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --always-on true \
    --min-tls-version "1.2" \
    --http20-enabled true \
    --ftps-state Disabled

# Set up health check
echo "Setting up health check..."
az webapp config set --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --health-check-path "/api/health"

# Configure custom domain and SSL
echo "Checking custom domain configuration..."
DOMAIN_EXISTS=$(az webapp config hostname list --webapp-name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --query "[?name=='$CUSTOM_DOMAIN'].name" -o tsv)

if [ -z "$DOMAIN_EXISTS" ]; then
    echo "Adding custom domain: $CUSTOM_DOMAIN"
    
    # Add the custom domain to the web app
    az webapp config hostname add --webapp-name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
        --hostname "$CUSTOM_DOMAIN"
    
    # Create and bind a managed certificate for the custom domain
    echo "Creating managed certificate for $CUSTOM_DOMAIN"
    az webapp config ssl create --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
        --hostname "$CUSTOM_DOMAIN" --only-enable-https
else
    echo "Custom domain $CUSTOM_DOMAIN is already configured."
fi

# Get the web app URL
WEBAPP_URL=$(az webapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --query defaultHostName -o tsv)

# Trigger deployment
echo "Triggering deployment..."
az webapp deployment source sync --name "$APP_NAME" --resource-group "$RESOURCE_GROUP"

# Print success message
echo ""
echo "============================================================="
echo "  Deployment Summary  "
echo "============================================================="
echo "Resource Group: $RESOURCE_GROUP"
echo "App Service Plan: $APP_SERVICE_PLAN"
echo "Web App: $APP_NAME"
echo "Web App URLs:"
echo "  - Default URL: https://$WEBAPP_URL"
echo "  - Custom Domain: https://$CUSTOM_DOMAIN"
echo "Application Insights: ${APP_NAME}-insights"
echo ""
echo "Partner Integration:"
echo "Tenant ID: $TENANT_ID"
echo "Partner Client ID: $CLIENT_ID"
echo ""
echo "Deployment has been triggered. It may take a few minutes for the app to be fully deployed."
echo "You can check the deployment status in the Azure Portal."
echo "Visit: https://portal.azure.com/#@$TENANT_ID/resource/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$APP_NAME/vstscd"
echo "============================================================="