from celery import shared_task
from .builder import DropperBuilder

@shared_task(bind=True)
def compile_dropper_task(self, config, dropper_type):
    """Celery task for async dropper compilation."""
    try:
        builder = DropperBuilder(config, dropper_type)
        return builder.build()
    except Exception as e:
        raise self.retry(exc=e, countdown=60)