from django import forms
from django.core.exceptions import ValidationError
from Account.models import User
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from django.core import validators


class UserCreationForm(forms.ModelForm):

    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Password confirmation", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ["phone", "fullname"]

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):

    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ["phone", "password", "fullname", "is_active", "is_admin"]





def start_with_0(value):
    if value[0] != '0':
        raise ValidationError("Please enter a first number 0")
class LoginForm(forms.Form):
    phone = forms.CharField(label="Phone Number", widget=forms.TextInput(attrs={'class' : 'form-control rounded-left' ,'placeholder' : 'Phone Number'}),validators=[start_with_0])
    password = forms.CharField(label="Password", widget=forms.PasswordInput(attrs={'class' : 'form-control rounded-left' ,'placeholder' : 'Password'}))




    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if len(phone) > 11:
            raise ValidationError(
                ("Invalid value: %(value)s is invalid"),
                code="invalid",
                params={"value": f"{phone}"},
            )
        elif len(phone) < 11:
            raise ValidationError("Phone number is too short",code='phone_length')
        return phone
def start_with_0(value):
    if value[0] != '0':
        raise ValidationError("Please enter a first number 0")
    elif len(value) > 11:
        raise ValidationError('The number of characters should not be more than 11')
    return value



class RegisterForm(forms.Form):
    phone = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Phone Number'}), validators=[start_with_0])
    fullname = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Enter Your Name'}))
    email = forms.CharField(required=False,max_length=250,widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Email(optional)'}))



class CheckOtpForm(forms.Form):
    code = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Enter Your Code'}),validators=[validators.ValidationError])



class ResetPasswordRequestForm(forms.Form):
    phone = forms.CharField(max_length=11, label="phone",widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Enter Your Phone Number'}))



class ResetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Confirm Password'}))

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("رمزهای عبور با هم مطابقت ندارند.")
        return cleaned_data





class OtpLoginForm(forms.Form):
    phone = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Enter Your Phone Number'}))



class CheckOtpCodeForm(forms.Form):
    code = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control rounded-left', 'placeholder': 'Enter Your Code'}),validators=[validators.ValidationError])