# Generated by Django 3.1.4 on 2020-12-01 21:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analyzerApp', '0003_auto_20201201_2057'),
    ]

    operations = [
        migrations.AlterField(
            model_name='uploadedtracesmodel',
            name='uploaded_at',
            field=models.DateTimeField(),
        ),
    ]
