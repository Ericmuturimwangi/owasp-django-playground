from django.urls import path
from .import views_vulnerable as vuln 
from .import views_secure as secure 

urlpatterns = [
    # vulnerbale
    path("vuln/login/", vuln.login_view),
    path("vuln/reset/", vuln.password_reset_request),
    path("vuln/documents/", vuln.document_list),
    path("vuln/documents/create/", vuln.document_create),
    path("vuln/documents/<int:pk>/", vuln.document_detail),
    # secure
    path("secure/login/", secure.login_view),
    path("secure/reset/", secure.password_reset_request),
    path("secure/documents/", secure.document_list),
    path("secure/documents/create/", secure.document_create),
    path("secure/documents/<int:pk>/", secure.document_detail),

]

