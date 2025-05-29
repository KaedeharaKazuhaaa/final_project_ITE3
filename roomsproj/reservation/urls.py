from django.urls import path
from . import views

urlpatterns = [
    # User authentication endpoints
    path('auth/user/register/', views.user_register, name='user-register'),
    path('auth/user/login/', views.user_login, name='user-login'),
    path('auth/user/', views.get_user_info, name='user-info'),
    path('auth/user/update/', views.update_user, name='update-user'),

    # Admin authentication endpoints
    path('auth/admin/register/', views.admin_register, name='admin-register'),
    path('auth/admin/login/', views.admin_login, name='admin-login'),

    # Common authentication endpoint
    path('auth/logout/', views.logout_view, name='logout'),

    # Room endpoints
    path('rooms/', views.room_list, name='room_list'),
    path('rooms/<int:pk>/', views.room_detail, name='room_detail'),

    # UserProfile endpoints
    path('profiles/', views.profile_list, name='profile-list'),
    path('profiles/<int:profile_id>/', views.profile_detail, name='profile-detail'),

    # Admin endpoints
    path('admins/', views.admin_list, name='admin-list'),
    path('admins/<int:admin_id>/', views.admin_detail, name='admin-detail'),
    path('reservations/pending/', views.pending_reservations, name='pending-reservations'),

    # Reservation endpoints
    path('reservations/', views.reservation_list, name='reservation-list'),
    path('reservations/<int:reservation_id>/', views.reservation_detail, name='reservation-detail'),

    # User listing endpoints
    path('users/', views.list_users, name='list_users'),
    path('users/<int:user_id>/', views.get_user_detail, name='user_detail'),
]