from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('login/google/', views.google_signin_start_view, name='google_signin_start'),
    path('post-auth/', views.post_auth_view, name='post_auth'),
    path('unlock/', views.unlock_data_view, name='unlock_data'),
    path('logout/', views.logout_view, name='logout'),
    path('2fa/setup/', views.setup_2fa_view, name='setup_2fa'),
    path('2fa/verify/', views.verify_2fa_view, name='verify_2fa'),
    path('2fa/recovery/email/', views.two_factor_recovery_email_request_view, name='two_factor_email_recovery_request'),
    path('2fa/recovery/email/<str:token>/', views.two_factor_recovery_email_confirm_view, name='two_factor_email_recovery'),
    path('2fa/recovery-codes/', views.recovery_codes_view, name='recovery_codes'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('password/reset/', views.BlindBitPasswordResetView.as_view(), name='password_reset'),
    path(
        'password/reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='registration/password_reset_done.html',
        ),
        name='password_reset_done',
    ),
    path(
        'password/reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='registration/password_reset_confirm.html',
            success_url='/accounts/password/reset/complete/',
        ),
        name='password_reset_confirm',
    ),
    path(
        'password/reset/complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='registration/password_reset_complete.html',
        ),
        name='password_reset_complete',
    ),
]
