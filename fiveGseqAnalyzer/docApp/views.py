
# Create your views here.
from django.shortcuts import render
from docApp.models import Category, Topic
from django.views.generic import TemplateView, View
from django.forms.models import model_to_dict
from django.contrib.auth.mixins import LoginRequiredMixin


# Create your views here.


class documentation(LoginRequiredMixin, TemplateView):
    login_url = 'login'
    redirect_field_name = 'redirect_to'
    template_name = "docApp/documentation.html"
    
    categoriz = Category.objects.order_by('order')
    data = Topic.objects.all().order_by('category', 'subOrder')
    def get(self, request, *args, **kwargs):
         return render(request, self.template_name, {'data': self.data, 'categoriz': self.categoriz})
