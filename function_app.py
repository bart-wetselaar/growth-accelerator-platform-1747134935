import azure.functions as func
import logging
from main import app

# Create a Flask-Function App bridge
app = func.WsgiMiddleware(app)

# Main entry point for the Function App
main = func.HttpTrigger(
    authLevel=func.AuthLevel.ANONYMOUS,
    methods=['GET', 'POST', 'PUT', 'DELETE'],
    route="{*route}"
)(app)