# Generated by Django 5.0.7 on 2024-08-08 10:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Account', '0007_otp_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='otp',
            name='token',
            field=models.CharField(max_length=200, null=True),
        ),
    ]