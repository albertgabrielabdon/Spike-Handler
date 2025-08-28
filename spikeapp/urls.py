from django.urls import path
from .views import SpikeHandlerView

urlpatterns = [
    path('', SpikeHandlerView.as_view(), name='spike-handler'),
]
