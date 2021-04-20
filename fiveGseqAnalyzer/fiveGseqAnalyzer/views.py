from django.shortcuts import render, redirect, reverse

# Create your views here.

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.views import View
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login

class HomeView(LoginRequiredMixin, TemplateView):
    login_url = 'login'
    redirect_field_name = 'redirect_to'
    template_name = 'home.html'
    # def get(self, request):
    #     return render(request, 'fiveGbp/home.html'
    # # def post(self, request):
    # #     return render(request, 'fiveGbp/home.html'


class LoginView(View):
    def get(self, request):
        return render(request, 'reginstration/login.html', { 'form':  AuthenticationForm })

    def post(self, request):
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data.get('username'),
                password=form.cleaned_data.get('password')
            )

            login(request, user)

            return redirect('/')
        return render(request, 'reginstration/login.html', { 'form': form })


class supportView(LoginRequiredMixin, View):
    login_url = 'login'
    redirect_field_name = 'redirect_to'
    def get(self, request):
        return render(request, 'support/support.html')

    def post(self, request):
        return render(request, 'support/support.html')
