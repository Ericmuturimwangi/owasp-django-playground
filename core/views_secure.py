import logging
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.http import require_http_methods
from .forms import SecureDocumentForm
from .logging_utils import sanitize, redact
from .models import Document
from .ratelimit import secure_is_rate_limited

log = logging.getLogger("app.security")

GENERIC_LOGIN_ERROR = "Invalid username or password."

@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "GET":
        return render(request, "login.html", {"mode": "secure"})

    
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")


    if secure_is_rate_limited(request, scope="login", identity=username, limit=5, window=300):

        log.warning("login throttled account=%s", sanitize(username))
        return HttpResponse(GENERIC_LOGIN_ERROR, status=429)

    log.info("login attempt %s", redact({"user": username, "password": password}))

    user = authenticate(request, username=username, password=password)
    if user is None:
        return HttpResponse(GENERIC_LOGIN_ERROR, status=401)

        login (request, user)
        return HttpResponseRedirect("/secure/documents")


@require_http_methods(["GET", "POST"])
def password_reset_request(request):

    if request.method == "GET":
        return render(request, "reset_request.html", {"mode": "secure"})

        email = request.POST.get("email", "")
        user = User.objects.filter(email=email).first()

        if user is not None:

            uid - urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            log.info("password reset issued %s", redact({"user": user.username}))

            _=f"/secure/reset/confirm/?uid={uid}&token={token}"

        return HttpResponse("If an account exists for that email, a reset link has been sent.")


@login_required(login_url="/secure/login/")
@require_http_methods("[GET]")
def document_detail(request, pk):
    
    doc = get_object_or_404(Document, pk=pk)
    if doc.owner_id != request.user.id and not doc.is_published:

        raise PermissionDenied

    return render(request, "document_detail.html", {"doc": doc, "mode": "secure"})

@login_required(login_url="/secure/login/")
@require_http_methods(["GET", "POST"])
def document_create(request):
    if request.method == "GET":
        return render(request, "document_form.html", 
                    {"form": SecureDocumentForm(), "mode": "secure"})


    form = SecureDocumentForm(request.POST)
    if form.is_valid():
        doc = form.save(commit=False)
        doc.owner = request.user 
        doc.save()
        return HttpResponseRedirect(f"/secure/documents/{doc.pk}")
    return render(request, "document_form.html", {"form": form, "mode": "secure"})


@login_required(login_url="/secure/login/")
@require_http_methods(["GET"])
def document_list(request):

    docs = Document.objects.filter(owner=request.user).order_by("pk")
    return render(request, "document_list.html", {"docs": docs, "mode": "secure"})
