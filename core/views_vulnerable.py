import base64
import logging
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods
from .forms import VulnerableDocumentForm
from .models import Document, PasswordResetToken
from .ratelimit import vulnerable_is_rate_limited

log = logging.getLogger("app.security")

@require_http_methods(["GET", "POST"])
def login_view(request):

    if request.method == "GET":
        return render (request, "login.html", {"mode": "vulnerable"})


    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    if vulnerable_is_rate_limited(request):
        return HttpResponse("Too many attempts", status=429)


    log.info(f"login attempt user={username} password={password}")

    try:
        user = User.objects.get(username=username)

    except User.DoesNotExist:

        return HttpResponse("No account with that username", status=401)

    if not user.check_password(password):

        return HttpResponse("Wrong password for that account", status=401)

    # vulnerable session fixation
    request.session["user_id"] = user.id 
    return HttpResponseRedirect("/vuln/documents/")


@require_http_methods(["GET", "POST"])
def password_reset_request(request):

    if request.method == GET:
        return render(request, "reset_request.html", {"mode": "vulnerable"})

    email = request.POST.get("email", "")

    try:
        user = User.objects.get(email=email)

    except User.DoesNotExist:

        return HttpResponse("No account uses that email", status=404)

    # vuln account enumeration through reset
    token = base64.urlsafe_b64decode(str(user.id).encode()).decode()
    PasswordResetToken.objects.create(user=user, token=token)

    return HttpResponse(f"Reset link: /vuln/reset/confirm/?token={token}")


@require_http_methods(["GET"])
def document_detail(request, pk):
    # vulnerable idor
    doc = get_object_or_404(Document, pk=pk)
    return render(request, "document_detail.html", {"doc":doc, "mode":"vulnerable"})


@require_http_methods(["GET", "POST"])
def document_create(request):
    # mass assignment 
    if request.method == "GET":
        return render (request, "document_form.html", 
            {"form": VulnerableDocumentForm(), "mode": "vulnerable"})

    form = VulnerableDocumentForm(request.POST)
    if form.is_valid():
        doc = form.save()
        return HttpResponseRedirect(f"/vuln/documents/{doc.pk}/")
    return render(request, "document_form.html", {"form": form, "mode": "vulnerable"})


@require_http_methods(["GET"])
def document_list(request):
    # list all documents regardless of the owner
    docs = Document.objects.all().order_by("pk")
    return render(request, "document_list.html", {"docs": docs, "mode": "vulnerable"})
