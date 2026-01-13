from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.views import View
from django.shortcuts import render,get_object_or_404
from .models import Student_detail
def index(request):
   resp1="""<html><body>HELLO from html
   <a href="/polls/home">Home page Page</a> 
   <p> Your Browser req is """+request.GET['guess']+ """ </p>
   </body></html>"""
   
   return HttpResponse(resp1)
def home(request):
    if request.method == 'POST':

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')

       
        print("First Name:", first_name)
        print("Last Name:", last_name)
        print("Email:", email)

        
        return render(request, 'polls/home.html', {'message': 'Registration Successful!'})

    
    return render(request, 'polls/home.html')

class Mainview(View):
   def get(self,request):
         #data=Student_detail.objects.get(pk=3)
         #x={"data":data}
         return render(request,'polls/landing-page.html')