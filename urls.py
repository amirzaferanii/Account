from django.urls import path
from . import views

app_name = 'account'


urlpatterns = [
    path('login', views.UserLoginView.as_view(), name='login'),
    path('otp_login', views.OtpLoginView.as_view(), name='otp_login_request'),
    path('check_otp_login', views.CheckOtpLoginView.as_view(), name='check_otp_login'),
    path('register', views.RegisterView.as_view(), name='register'),
    path('check_otp', views.CheckOtpView.as_view(), name='check_otp'),
    path('logout', views.UserLogoutView.as_view(), name='logout'),
    path('reset_password_request', views.ResetPasswordRequestView.as_view(), name='reset_password_request'),
    path('reset_password_confirm', views.ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    path('reset-password-complete/', views.ResetPasswordCompleteView.as_view(), name='reset_password_complete'),

]