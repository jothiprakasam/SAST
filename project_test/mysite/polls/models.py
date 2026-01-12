from django.db import models

# Create your models here.
class Student_detail(models.Model):
    name=models.CharField(max_length=128)
    age=models.IntegerField(max_length=5)

