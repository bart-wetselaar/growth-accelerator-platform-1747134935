# Growth Accelerator Staffing Platform

A dynamic Staffing Platform leveraging advanced technologies to streamline job matching and application processes with robust backend integrations.

## Core Technologies

- Flask web framework
- Python backend with comprehensive service integrations
- Advanced circuit breaker pattern for API resilience
- Real-time job data processing
- Multi-platform job board interface
- OAuth authentication
- Responsive design with enhanced error handling
- Unified dashboard for candidate and job management
- Workable API integration for real-time job listings

## Getting Started

### Local Development

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/growth-accelerator-staffing.git
   cd growth-accelerator-staffing
   ```

2. Set up environment variables:
   - Create a `.env` file with the required variables (see below)

3. Run with Docker Compose:
   ```bash
   docker-compose up
   ```

4. Access the application at http://localhost:8000

### Required Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `WORKABLE_API_KEY`: API key for Workable
- `LINKEDIN_CLIENT_ID`: Client ID for LinkedIn API
- `LINKEDIN_CLIENT_SECRET`: Client secret for LinkedIn API
- `SQUARESPACE_API_KEY`: API key for Squarespace
- `SESSION_SECRET`: Secret key for session encryption

## Deployment

This application is designed for deployment on Microsoft Azure. For complete deployment instructions, see:

- [Azure Deployment Guide](AZURE_DEPLOYMENT.md)
- [Azure Quick Start Guide](AZURE_QUICK_START.md)
- [Custom Domain Setup](AZURE_CUSTOM_DOMAIN.md)

### Continuous Integration and Deployment

This repository is configured with GitHub Actions for automated CI/CD:

1. Push to the `main` branch triggers the workflow
2. Tests are run and code coverage is reported
3. A Docker image is built and pushed to GitHub Container Registry
4. The image is deployed to Azure Web App

For more details, see [GitHub Actions Setup](.github/GITHUB_ACTIONS_SETUP.md)

## Monitoring and Uptime

The application includes enterprise-grade monitoring and uptime solutions:

- [Monitoring Guide](MONITORING_README.md)
- [Uptime Guide](UPTIME_README.md)

## Architecture

The Growth Accelerator Staffing Platform consists of three main sections:

1. **Staffing**: Workflow from client onboarding through job matching and hiring to consultant onboarding
2. **Services**: Workspace with integrations for LinkedIn Business Manager, LinkedIn Campaign Manager, and Growth Accelerator's LinkedIn page
3. **Contracting**: API integration with backoffice for hourly registration and payments

## Feature Highlights

- Real-time Workable API integration across all platform sections
- Circuit breaker pattern for API resilience
- Responsive design for mobile and desktop
- LinkedIn OAuth integration
- Enterprise-grade deployment architecture with Docker containers
- Comprehensive monitoring with Azure Application Insights
- Continuous Integration/Continuous Deployment with GitHub Actions

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

This project is proprietary and confidential. All rights reserved.

## Support

For support, please contact the Growth Accelerator IT team.