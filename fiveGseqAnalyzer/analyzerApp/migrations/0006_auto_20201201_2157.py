# Generated by Django 3.1.4 on 2020-12-01 21:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analyzerApp', '0005_auto_20201201_2156'),
    ]

    operations = [
        migrations.AlterField(
            model_name='uploadedtracesmodel',
            name='uploaded_at',
            field=models.DateTimeField(),
        ),
    ]
