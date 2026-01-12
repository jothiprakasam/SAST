from django.urls import path
from . import views
from .views import Mainview
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin


urlpatterns = [
    path('/', views.index, name='index'),
    path('admin/', admin.site.urls, name='admin'),
    path('index/', views.index, name='index'),
    path('home/', views.home, name='home'),
    path('main/', Mainview.as_view(), name='main_view'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)