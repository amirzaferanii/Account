# Generated by Django 5.0.7 on 2024-08-13 08:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Account', '0011_alter_otp_unique_together_otpcode'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(blank=True, max_length=255, null=True, verbose_name='آدرس ایمیل'),
        ),
    ]
