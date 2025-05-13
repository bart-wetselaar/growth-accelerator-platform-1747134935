# This is a bridge file to maintain compatibility with existing imports
# All actual models are now in db/models.py

# Import db from our new db module
from db import db

# Import all models from the new module
from db.models import UserRole, User, Consultant, Skill, ConsultantSkill
from db.models import Client, Job, JobSkill, ApplicationStatus, Application
from db.models import Interview, Placement, OnboardingData, ApiLog
# Import feedback and matching models
from db.models import (FeedbackCategory, FeedbackStatus, Feedback, 
                      FeedbackResponse, MatchScore, MatchingWeights)

# No duplicated class definitions - everything is imported from db/models.py
