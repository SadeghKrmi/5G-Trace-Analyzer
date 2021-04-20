from django.db import models

# Create your models here.
class Category(models.Model):
    order = models.IntegerField(unique=True)
    name = models.CharField(max_length=20, unique=True)
    # class Meta:
    #     verbose_name = 'Category'
    #     verbose_name_plural = 'Categories'
    #     ordering = ['order']
    
    def __str__(self):
        return self.name
        

class Topic(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    subOrder = models.IntegerField()
    title = models.CharField(max_length=255)
    body = models.TextField()
    
    def __str__(self):
        return "%s - %s" % (self.category, self.title)
    
