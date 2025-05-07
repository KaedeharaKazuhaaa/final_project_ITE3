from django.urls import path
from . import views

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.register, name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/user/', views.get_user_info, name='user-info'),

    # Room endpoints
    path('rooms/', views.room_list, name='room_list'),
    path('rooms/<int:pk>/', views.room_detail, name='room_detail'),

    # UserProfile endpoints
    path('profiles/', views.profile_list, name='profile-list'),
    path('profiles/<int:profile_id>/', views.profile_detail, name='profile-detail'),

    # Admin endpoints
    path('admins/', views.admin_list, name='admin-list'),
    path('admins/<int:admin_id>/', views.admin_detail, name='admin-detail'),

    # Reservation endpoints
    path('reservations/', views.reservation_list, name='reservation-list'),
    path('reservations/<int:reservation_id>/', views.reservation_detail, name='reservation-detail'),
]