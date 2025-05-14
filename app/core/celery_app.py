from celery import Celery
from app.core.config import settings

# Initialize Celery
# The first argument is the name of the current module, this is important for autodiscovery of tasks.
# The broker and backend are taken from the settings.
celery_app = Celery(
    "guardpost_tasks", # Can be any name, but usually matches the project
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        'app.services.tasks.blast_radius_calculator', # Add other task modules here
        # Add other task modules here, e.g., 'app.services.tasks.reporting_tasks'
    ]
)

# Optional Celery configuration, see Celery docs for more options
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    # Optional: Add task routing, rate limits, etc.
    # task_routes = {
    #     'app.services.tasks.blast_radius_calculator.calculate_node_blast_radius': {'queue': 'blast_radius'},
    # },
)

if __name__ == '__main__':
    # This allows running the worker directly using `python -m app.core.celery_app worker ...`
    # Though usually it's run via `celery -A ...` command.
    celery_app.start() 