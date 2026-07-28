import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("stubs", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="LearningPackage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
            ],
        ),
        migrations.AddField(
            model_name="contentlibrary",
            name="learning_package",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="stubs.learningpackage",
            ),
        ),
    ]
