from django.db import models
from django.conf import settings

class Document(models.Model):

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="documents"
    )

    title = models.CharField(max_length=200)
    body = models.TextField(blank=True)

    is_published = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Document<{self.pk} owner={self.owner_id} '{self.title}'>"


class PasswordResetToken(models.Model):

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    token = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    
