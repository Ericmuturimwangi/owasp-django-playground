from django import forms

from .models import Document

class VulnerableDocumentForm(forms.ModelForm):

    class Meta:
        model = Document
        fields = "__all__"


class SecureDocumentForm(forms.ModelForm):

    class Meta:
        model = Document
        fields = ["title", "body"]

        