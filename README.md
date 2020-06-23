				Asp.Net Core InProcessing Hosting

In Programm.cs file, we have Main Method and this is the entry point for application

Main method calls CreateWebHostBuilder(args).Build().Run method

CreateWebHostBuilder calls CreateDefaultBuilder() and setsups the WebHost that host the our applications with preconfigured defaults


Tasks Performed By CreateDefaultBuilder Method :

1)Setting up the web server
2)Loading the host and application configuration from various configuration soruces and 
3)Configuring logging

Asp.Net core app can be hosted
1)InProcess
2)OutOfProcess


InProcess Hosting :

<AspNetCoreHostingModel>InProcess</AspNetCoreHostingModel>


Create Default Builder() method calls UseIIS() method and host the app inside of the iis worker process(w3wp.exe or iisexpress.exe)
------------------------------------------------------------------------
Kestrel :

Cross-Platform web server for ASP.NET Core
Kestrel can be used, by itself as an edge server
the process used to host the app is dotnet.exe






							Middleware in ASP.NET Core

1)Has access to both Request and Response
2)May simply pass the Request to next Middleware
3)May process and then pass the Request to next Middleware
4)May handle the Request and short-circuit the pipeline
5)May Process the outgoing Response
6)Middlewares are executed in the order they are added


					Configuring ASP.NET Core request processing pipeline

app.Run method is a Terminal Middleware,so next middleware will not be executed

if multiple middlewares are present, we should use app.Use(context, Next) method 

app.UseStaticFiles(); for accessing static files

app.UseDefaultFiles(); for execute default files, it should be before UseStaticFiles() 

Ex: Custome Default Files :

DefaultFilesOptions defaultFilesOptions = new DefaultFileOPtions();
defaultFilesOPtions.DefaultFileNames.Clear();
defaultFilesOptions.DefaultFIleNames.Add("newfile.html");
app.UseDefaultFiles(defaultFilesOptions);



we can replace staticfiles and defaultfiles middlewares with UseFileServer() middleware

Ex:

FileServerOptions fileServerOptions = new FileServerOptions();
fileServerOptions.DefaultFilesOptions.DefaultFileNames.Clear();
fileServerOptions.DefaultFilesOptions.DefaultFileNames.Add("newfile.html");

app.UseFileServerFiles(fileServerOptions);








					AddMVC vs AddMvcCore
 All JsonResult,ViewResult are inherited from controller base class in the namespace (Microsoft.aspnetcore.Mvc)

 For Simple return type,we need to add controller

 1)AddMvcCore() method only adds the core MVC services.
 2)AddMvc() method adds all the required MVC services.
 3)AddMvc() method calls AddMvcCore() method internally.

To Register with Dependency Injection Container

1)AddSingleton() --> Single Instance will be created per application lifetime
2)AddTransient() -->Each request will create new instance
3)AddScoped() --> Once per request within the scope.



				Tag Helpers

=>new to asp.net core mvc

<a asp-controller="home" aso-action="details" asp-route-id="1">View</a>

image tag helper enhances the <img> tag to provide cache-busting behaviour for static image files
Based on the content of image,a unique hash value is calculated and appended to image URL

Each time the image on the server changes a new hash value is calculated and cached


Environment Tag Helper :

The application environment name is set using ASPNETCORE_ENVIRONMENT variable
-Environment tag helper supports rendering different content depending on the application environment
<environment include="Development">
	<link rel="stylesheet"
			href=""
	>
</environment>

app.useMvc(routes => {
	routes.MapRoute("default","{controller=Home}/{action=Index}/{id?}");
});


						FORM TAG HELPERS

Form Tag Helper
Input Tag Helper
Label Tag Helper
Select Tag Helper
TextArea Tag Helper
Form Validation Tag Helper


				Model Binding

Model binding maps data in an HTTP request to controller action method parameters

The action parameters may be simple types such as integers, strings etc or complex types like Customer, Employee, Order etc

To bind the request data to the controller action method parameters, model bindings looks for data in the http request

 Form Values ==> Route Values ==> Query Strings




 					Entity Framework Core

It is ORM(Object-Relational Mapper)
Lightweight,Extensible and Open Source
Work Cross Platform
Microsoft's Official Data Access Platform

-->Database and Code first approches

Install EF Core
--------------------------

If we use multi-layer and data access layer as seperate one,we need to install EF core
Microsoft.EntityFrameworkCore.SqlServer  == >>  Microsoft.EntityFrameworkCore.Relational ==>> Microsoft.EntityFrameworkCore

To use DbContext class in our application, create a class that derives ffrom the DbContext class

public class AppDbContext : DbContext{
	public AppDbContext(DbContextOptions<AppDbContext> options):base(options){

	}
	pu
}

-> The DbContext class includes a DBset<TEntity> property for each entity in the model
->The LINQ queries against the DbSet<TEnity> will be translated into queries against the underlying database

Repository pattern is abstraction of underlying database



MIGRATIONS :

1)add-migration migrationName
2)update-database
3)Remove-migration : removes the latest migration that was not updated to database
4)update-database "migration_name" : this will revert the changes to migrations mentioned,so we can remove migrations those were already applied after it

							Logging in AspNetCore

Default Logging :
--------------------
output window in visual studio(If we run from vsstudio or it is in console) 

To prevent this messages in output window ==> Tools->Option->Debbugging-->Turrnoff messages


Built-in LLogging Providers :
--------------------------------------

Console
Debug
Eventsource 
Eventlog
TraceSource
AzureAppServicesFile
AzureAppServicesBlob
ApplicationInsights

Third Party Logging Providers
-------------------------------

NLog
elmah
Serilog
Sentry
JSNLog
Loggr
Gelf



Sample Error Method For Exception(Displaying in view)
------------------------------

[Route("Error")]
public IActionResult Error(){
	
	var exceptionDetails = HttpContext.Features.Get<>(IExceptionHandlerPathFeature);
	ViewBag.ExceptionPath = exceptionDetails.Path;
	Viewba.ExceptionMessage = exceptionDetails.Error.Message;
	ViewBag.StackTrace = exceptionDetails.Error.StackTrace;

	return View("Error");
}


Logging Exception Details :
------------------------------------

public class ErrorController :Controller{
	privare readonly ILogger<ErrorController> logger;
	Public ErrorController(ILogger<ErrorController> logger){
		this.logger = logger
	}


	[Route("Error")]
	public IActionResult Error(){
	
		var exceptionDetails = HttpContext.Features.Get<>(IExceptionHandlerPathFeature);
		
		logger.LogError($"The path {exceptionDetails.Path} threw an exception {exceptionDetails.Error.Message}");
	}



	Logging to file in asp net core using NLOG
	-------------------------------------------------

	To use NLog in ASP.NET Core

Step 1 : Install NLog.Web.AspNetCore nuget package

Once the NLog package is iinstalled, you will see the PackageReference included in the .csproj file

Step 2 : Create nlog.config file

Create nlog.config file in the root of your project. Please use the configuration available at the following link.
https://csharp-video-tutorials.blogsp...

To learn more about the nlog.config file please refer to the following github wiki page
https://github.com/NLog/NLog/wiki/Con...

Step 3 : Enable copy to bin folder

Right click on nlog.config file in the Solution Explorer and select Properties. In the Properties window set 
Copy to Output Directory = Copy if newer

Step 4 : Enable NLog as one of the Logging Provider

In addition to using the default logging providers (i.e Console, Debug & EventSource), we also added NLog using the extension method AddNLog(). This method is in NLog.Extensions.Logging namespace.

public class Program
{
    public static void Main(string[] args)
    {
        CreateWebHostBuilder(args).Build().Run();
    }

    public static IWebHostBuilder CreateWebHostBuilder(string[] args) =]
        WebHost.CreateDefaultBuilder(args)
        .ConfigureLogging((hostingContext, logging) =]
        {
            logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
            logging.AddConsole();
            logging.AddDebug();
            logging.AddEventSourceLogger();
            // Enable NLog as one of the Logging Provider
            logging.AddNLog();
        })
        .UseStartup[Startup]();
}

If you want only NLog as the logging provider, clear all the logging providers and then add NLog.

public class Program
{
    public static void Main(string[] args)
    {
        CreateWebHostBuilder(args).Build().Run();
    }

    public static IWebHostBuilder CreateWebHostBuilder(string[] args) =]
        WebHost.CreateDefaultBuilder(args)
        .ConfigureLogging((hostingContext, logging) =]
        {
            // Remove all the default logging providers
            logging.ClearProviders();
            logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
            // Add NLog as the Logging Provider
            logging.AddNLog();
        })
        .UseStartup[Startup]();
}








AspNet Core LogLevel Configuration
-------------------------------------------

LogLevel indicates the severity of the logged message. It can be any of the following. They are listed here from lowest to highest severity.
Trace = 0
Debug = 1
Information = 2
Warning = 3
Error = 4
Critical = 5
None = 6

LogLevel Enum 

LogLevel enum is present in Microsoft.Extensions.Logging namespace

namespace Microsoft.Extensions.Logging
{
    public enum LogLevel
    {
        Trace = 0,
        Debug = 1,
        Information = 2,
        Warning = 3,
        Error = 4,
        Critical = 5,
        None = 6
    }
}

LogLevel in appsettings.json 

LogLevel setting in appsettings.json file is used to control how much log data is logged or displayed. 

"Logging": {
  "LogLevel": {
    "Default": "Trace",
    "Microsoft": "Warning"
  }
}

ILogger Methods

On the ILogger interface, we have log methods that include the log level in the method name. For example to log a TRACE message we use LogTrace() method. Similarly to log a WARNING message we use LogWarning() method. Notice, except for LogLevel = None, we have a corresponding method for every log level.

LogTrace()
LogDebug()
LogInformation()
LogWarning()
LogError()
LogCritical()

LogLevel Example

Consider the following Details() action in HomeController

public class HomeController : Controller
{
    public ViewResult Details(int? id)
    {
        logger.LogTrace("Trace Log");
        logger.LogDebug("Debug Log");
        logger.LogInformation("Information Log");
        logger.LogWarning("Warning Log");
        logger.LogError("Error Log");
        logger.LogCritical("Critical Log");

        // Rest of the code
    }
}

The following is the LogLevl configuration in appsettings.json file.

"Logging": {
  "LogLevel": {
    "Default": "Trace",
    "Microsoft": "Warning"
  }
}

The following Log output is displayed in the Debug Output window. Since we have set "Default": "Trace", we see everything from Trace level and higher. Since Trace is the lowest level we see all the logs.

EmployeeManagement.Controllers.HomeController:Trace: Trace Log
EmployeeManagement.Controllers.HomeController:Debug: Debug Log
EmployeeManagement.Controllers.HomeController:Information: Information Log
EmployeeManagement.Controllers.HomeController:Warning: Warning Log
EmployeeManagement.Controllers.HomeController:Error: Error Log
EmployeeManagement.Controllers.HomeController:Critical: Critical Log

However if you want WARNING and higher then set "Default": "Warning"

If you do not want anything logged set LogLevel to None. The integer value of LogLevel.None is 6, which is higher than all the other log levels. So nothing gets logged.

Log filtering in ASP.NET Core

Consider the following log statement

EmployeeManagement.Controllers.HomeController:Trace: My log message

EmployeeManagement.Controllers.HomeController is the LOG CATEGORY
Trace is the LOG LEVEL. Remeber log level can be (Trace, Debug, Information, etc...)

In simple terms, LOG CATEGORY is the fully qualified name of the class that logged the message. The log category is displayed as a string in the logged message so we can use it easily determine from which class the log came from. LOG CATEGORY is used to filter logs.


-------------------------------------------------------------------------------
								ASP NET CORE IDENTITY
public class AppDbContext : IdentityDbContext
{
	public AppDbContext(DBContextOptions<AppDbContext> options) :base(options){


	}

	public DBSet<Employee> EMployees{get;set;}
	protected override void OnModelCreating(ModelBuilder model){

	base.OnModelCreating(modelBuilder);
	modelBuilder.Seed();
	}

}


}

In Startup.cs==>Configure Services:

services.AddIdentity<IdentityUser,IdentityRole>();
        .AddEntityFrameworkStores<AppDbContext>();


In CongiureMethod, Add UseAuthentication() before mvc middleware
app.UseAuthentication()



---------------------------------------------------------
Register New User using aspnet core identity

To be able to register as a new user we need an email address and password.

RegisterViewModel Class

We will use this RegisterViewModel Class as the model for Register view. It carries the information from the view to the controller class. For validation we are using several asp.net core validation attributes. We discussed these validation attributes and model validation in detail in Parts 42 and 43 of this video series.

public class RegisterViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = "Confirm password")]
    [Compare("Password",
        ErrorMessage = "Password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }
}

HttpGet Register action in AccountController

All the user account related CRUD operations will be in this AccountController. 
At the moment we just have the Register action method
We reach this action method by issuing a GET request to /account/register

using Microsoft.AspNetCore.Mvc;

namespace EmployeeManagement.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
    }
}

Register View

Place this view in Views/Account folder
The model for this view is RegisterViewModel which we created above

For the Register View HTML please refer to our blog at the following link
https://csharp-video-tutorials.blogspot.com/2019/06/register-new-user-using-aspnet-core.html

In our next video we will discuss 
Implementing Register action that handles HttpPost to /account/register
Create a user account using the posted form data and asp.net core identity



----------------------------------------------
AspNet Core Identiy UserManager and SignInManager

UserManager<IdentityUser> class contains the required methods to manage users in the underlying data store. For example, this class has methods like CreateAsync, DeleteAsync, UpdateAsync to create, delete and update users.

SignInManager<IdentityUser> class contains the required methods for users signin. For example, this class has methods like SignInAsync, SignOutAsync to signin and signout a user.

Both UserManager and SignInManager services are injected into the AccountController using constructor injection

Both these services accept a generic parameter. We use the generic parameter to specify the User class that these services should work with. 

At the moment, we are using the built-in IdentityUser class as the argument for the generic parameter.

The generic parameter on these 2 services is an extension point. 

This means, we can create our own custom user with any additional data that we want to capture about the user and then plug-in this custom class as an argument for the generic parameter instead of the built-in IdentityUser class. 

For the code of the Register action method please refer to our blog at the following link
https://csharp-video-tutorials.blogspot.com/2019/06/aspnet-core-identity-usermanager-and.html

At this point if you run the project and provide a valid email address and password, the user account should be created in AspNetUsers table in the underlying SQL server database. You could view this data from SQL Server Object Explorer in Visual Studio.


------------------------------------------------------------------
ASP NET core identity password complexity


By default, asp.net core identity does not allow creating simple passwords to protect our application from automated brute-force attacks. When we try to register a new user account with a simple password like abc, the account creation fails and you will see validation errors related to password complexity.

ASP.NET Core Identity Password Default Settings

In ASP.NET Core Identity, Password Default Settings are specified in the PasswordOptions class. You can find the source code of this class on the asp.net core github repo at the following link. Simply search in the repo for the PasswordOptions class.
https://github.com/aspnet/AspNetCore

public class PasswordOptions
{
    public int RequiredLength { get; set; } = 6;
    public int RequiredUniqueChars { get; set; } = 1;
    public bool RequireNonAlphanumeric { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireDigit { get; set; } = true;
}

How to override password default settings in asp.net core identity

We could do this by, using the Configure() method of the IServiceCollection interface in the ConfigureServices() method of the Startup class

services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 10;
    options.Password.RequiredUniqueChars = 3;
    options.Password.RequireNonAlphanumeric = false;
});

OR

We could also do this while adding Identity services 

services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 10;
    options.Password.RequiredUniqueChars = 3;
    options.Password.RequireNonAlphanumeric = false;
})
.AddEntityFrameworkStores[AppDbContext]();

ASP.NET Core IdentityOptions 

In this example, we are using the IdentityOptions object to configure PasswordOptions. We could also use this IdentityOptions object to configure
UserOptions
SignInOptions
LockoutOptions
TokenOptions
StoreOptions
ClaimsIdentityOptions

------------------------------------------------------------------------
								Show or hide login and logout links based on login status in asp net core


If the user is not logged-in, display Login and Register links.

If the user is logged-in, hide Login and Register links and display Logout link.

Inject SignInManager, so we could check if the user is signed-in

For code used in the demo, please refer to our blog at the following link
https://csharp-video-tutorials.blogspot.com/2019/06/show-or-hide-login-and-logout-links.html

Use a POST request to log the user out. Using a GET request to log out the user is not recomended because the approach may be abused. A malicious user may trick you into clicking an image element where the src attribute is set to the application logout url. As a result you are unknowingly logged out.

Logout user in asp.net core


-----------------------------------------------------------------------------------

							Implementing login functionality in asp net core

To implement the login functionality in an asp.net core application, we need
Login View Model
Login View
A pair of Login action methods in the AccountController - HttpGet login Action and HttpPost login Action

LoginViewModel

To login a user, we need their Email which is the username, password and whether if they want a persistent cookie or session cookie.

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }
}

Session Cookie vs Persistent Cookie

Upon a successful login, a cookie is issued and this cookie is sent with each request to the server. The server uses this cookie to know that the user is already authenticated and logged-in. This cookie can either be a session cookie or a persistent cookie.

A session cookie is created and stored within the session instance of the browser. A session cookie does not contain an expiration date and is permanently deleted when the browser window is closed.

A persistent cookie on the other hand is not deleted when the browser window is closed. It usually has an expiry date and deleted on the date of expiry.

For Login View Code and Login Action Methods code
https://csharp-video-tutorials.blogspot.com/2019/06/implementing-login-functionality-in.html


-------------------------------------------------------------------------------

								Authorization in ASP NET Core

What is Authorization in ASP.NET Core

Authentication is the process of identifying who the user is. 
Authorization is the process of identifying what the user can and cannot do.
For example, if the logged in user is an administrator he may be able to Create, Read, Update and Delete orders, where as a normal user may only view orders but not Create, Update or Delete orders.
Authorization in ASP.NET Core MVC is controlled through the AuthorizeAttribute

Authorize Attribute in ASP.NET Core
When the Authorize Attribute is used in it's simplest form, without any parameters, it only checks if the user is authenticated.

Authorize Attribute Example

As the Authorize attribute is applied on the Controller, it is applicable to all the action methods in the controller. The user must be logged in, to access any of the controller action methods.

[Authorize]
public class HomeController : Controller
{
    public ViewResult Details(int? id)
    { 
    }
        
    public ViewResult Create()
    {   
    }
        
    public ViewResult Edit(int id)
    {
    }
}

Authorize attribute can be applied on individual action methods as well. In the example below, only the Details action method is protected from anonymous access.

public class HomeController : Controller
{
    [Authorize]
    public ViewResult Details(int? id)
    {
    }

    public ViewResult Create()
    {
    }

    public ViewResult Edit(int id)
    {
    }
}

AllowAnonymous Attribute in ASP.NET Core

As the name implies, AllowAnonymous attribute allows anonymous access. We generally use this attribute in combination with the Authorize attribute.

AllowAnonymous Attribute Example

As the Authorize attribute is applied at the controller level, all the action methods in the controller are protected from anonymous access. However, since the Details action methos is decorated with AllowAnonymous attribute, it will be allowed anonymous access.

[Authorize]
public class HomeController : Controller
{
    [AllowAnonymous]
    public ViewResult Details(int? id)
    {
    }

    public ViewResult Create()
    {
    }

    public ViewResult Edit(int id)
    {
    }
}

Please note: If you apply [AllowAnonymous] attribute at the controller level, any [Authorize] attribute attributes on the same controller (or on any action within it) is ignored.

Apply Authorize attribute globally

To apply [Authorize] attribute globally on all controlls and controller actions throught your application modify the code in ConfigureServices method of the Startup class.

public void ConfigureServices(IServiceCollection services)
{
    // Other Code

    services.AddMvc(config =] {
        var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
        config.Filters.Add(new AuthorizeFilter(policy));
    });

    // Other Code
}

AuthorizationPolicyBuilder is in Microsoft.AspNetCore.Authorization namespace
AuthorizeFilter is in Microsoft.AspNetCore.Mvc.Authorization namespace

If you do not have [AllowAnonymous] attribute on the Login actions of the account controller you will get the following error because the application is stuck in an infinite loop. 

HTTP Error 404.15 - Not Found

The request filtering module is configured to deny a request where the query string is too long.

Most likely causes:
Request filtering is configured on the Web server to deny the request because the query string is too long.

You try to access /Account/login
Since the [Authorize] attribute is applied globally, you cannot access the URL /Account/login
To login you have to go to /Account/login
So the application is stuck in this infinite loop and every time we are redirected, the query string ?ReturnUrl=/Account/Login is appended to the URL
This is the reason we get the error - Web server denied the request because the query string is too long.

To fix this error, decorate Login() actions in the AccountController with [AllowAnonymous] attribute.

In addition to this simple authorization, asp.net core supports role based, claims based and policy based authorization. We will discuss these authorization techniques in our upcoming videos.


-------------------------------------------------------------------------------

What happens when we try to navigate to a URL, to which we do not have access

By default, ASP.NET Core redirects to the Login URL with ReturnUrl query string parameter. The URL that we were trying to access will be the value of the ReturnUrl query string parameter.

ReturnUrl Query String Example

In this example, ReturnUrl is set to ReturnUrl=/home/create. I was trying to Create a New Employee by navigating to /home/create without first signing in. Since I do not have access to /home/create until I login, ASP.NET core redirected to the login URL which is /Account/Login with the query string parameter ReturnUrl 

http://localhost:4901/Account/Login?ReturnUrl=%2Fhome%2Fcreate


The characters %2F are the encoded charactes for a forward slash (/). To decode these chracters in the URL, you may use the following website.
https://meyerweb.com/eric/tools/dencoder/

Redirect to ReturnUrl after Login

ASP.NET Core model binding automatically maps the value 
from the URL query string parameter ReturnUrl 
to the Login() action method parameter returnUrl
ASP.NET Core Redirect(returnUrl) method, redirects the user to the specified returnUrl

[HttpPost]
[AllowAnonymous]
public IActionResult Login(LoginViewModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        var result = signInManager.PasswordSignInAsync(model.Email,
            model.Password, model.RememberMe, false);

        if (result.Succeeded)
        {
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("index", "home");
            }
        }

        ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
    }

    return View(model);
}

There is a serious flaw in the way we have used the ReturnUrl query string parameter. This opens a serious security hole with in our application which is commonly known as open redirect vulnerability. 


-------------------------------------------------------------------
					Open redirect vulnerability example

Application Vulnerable to Open Redirect Attacks

Your application is vulnerable to open redirect attacks if the following 2 conditions are true

Your application redirects to a URL that's specified via the request such as the querystring or form data

The redirection is performed without checking if the URL is a local URL

What is Open Redirect Vulnerability 

Most of the web applications redirect users to a login page when they access resources that require authentication. For example, to see the list of all orders, you must be already logged in. If you are not logged in and try to see the list of orders, by navigating to http://example.com/orders/list, you will be redirected to the login page. 

The redirection includes a returnUrl querystring parameter so that the user can be returned to the originally requested URL after they have successfully logged in. 

http://example.com/Account/Login?ReturnUrl=/orders/list

A malicious user can use this returnUrl querystring parameter to initiate an open redirect attack.

Open Redirect Vulnerability Example

The user of your application is tricked into clicking a link in an email where the returnUrl is set to the attackers website. 

http://example.com/account/login?returnUrl=http://exampie.com/account/login (the returnUrl is "exampie.com", instead of "l" there is an "i")

The user logs in successfully on the authentic site and he is then redirected to the attackers website (http://exampie.com/account/login)

The login page of the attackers website looks exactly like the authentic site.

The user logs in again on the attackers website, thinking that the first login attempt was unsuccessful

The user is then redirected back to the authentic site.

During this entire process, the user does not even know his credentials are stolen.

Prevent open redirect attacks in ASP.NET Core

We have an open redirect vulnerability beacuse, the URL is supplied to the application from the querystring. We are simply redirecting to that URL without any validation which is what is making our application vulnerable to open redirect attacks.

To prevent open redirect attacks, check if the provided URL is a local URL or you are only redirecting to known trusted websites.

ASP.NET Core has built-in support for local redirection. Simply use the LocalRedirect() method. If a non-local URL is specified an exception is thrown.

public IActionResult Login(string returnUrl)
{
    return LocalRedirect(returnUrl);
}

To check if the provided URL is a local URL, use IsLocalUrl() method.

public IActionResult Login(string returnUrl)
{
    if (Url.IsLocalUrl(returnUrl))
    {
        return Redirect(returnUrl);
    }
    else
    {
        return RedirectToAction("index", "home");
    }



-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
																		ASP NET Core client side validation

Use unobtrusive client-side validation libraries provided by asp.net core.

With this approach, we do not have to write a single line of code. All we have to do is include the following 3 scripts in the order specified.

jquery.js
jquery.validate.js
jquery.validate.unobtrusive.js

What does "Unobtrusive Validation" Mean

Unobtrusive Validation allows us to take the already-existing server side validation attributes and use them to implement client-side validation. We do not have to write a single line of custom JavaScript code. All we need is the above 3 script files in the order specified.

How does client side validation work in ASP.NET Core

ASP.NET Core tag helpers work in combination with the model validation attributes and generate the following HTML. Notice in the generated HTML we have data-* attributes.

[input id="Email" name="Email" type="email" data-val="true"
        data-val-required="The Email field is required." /]

The data-* attributes allow us to add extra information to an HTML element. These data-* attributes carry all the information required to perform the client-side validation. It is the unobtrusive library (i.e jquery.validate.unobtrusive.js) that reads these data-val attributes and performs the client side validation.

Unobtrusive validation not working in ASP.NET Core

Make sure browser support for JavaScript is not disabled

Make sure the following client-side validation libraries are loaded in the order specified
jquery.js
jquery.validate.js
jquery.validate.unobtrusive.js

Make sure these validation libraries are loaded for the environment you are testing against. Development, Staging, Production etc.

If there's another reason why client side validation is not working, please leave it as a comment so it could help others.

We discussed implementing, server side validation in Parts 42 and 43 of ASP.NET Core tutorial. Server side validation is implemented by using validation attributes such as Required, StringLength etc. As the name implies, server side validation is done on the server. So there is a round trip between the client browser and the web server. The request has to be sent over the network to the web server for processing. This means if the network is slow or if the server is busy processing other requests, the end user may have to wait a few seconds and it also increases load on the server. This validation can be performed on the client machine itself, which means there is no round trip to the server, no waiting time, client has instant feedback and the load on the server is also reduced to a great extent.

Server Side Validation Example

On the login page, Email and Password fields are required. To make the Email and Password fields required, we decorate the respective model properties with the [Required] attribute. We discussed how to use these validation attributes and implement server side model validation in our previous videos in this series. These same validation attributes are also used to implement client side validation in asp.net core.

public class LoginViewModel
{
    [Required]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }
}

Client Side Validation

With unobtrusive client-side validation we do not have to write a single line of code. All we have to do is include the following 3 scripts in the order specified.

jquery.js
jquery.validate.js
jquery.validate.unobtrusive.js

What does "Unobtrusive Validation" Mean

Unobtrusive Validation allows us to take the already-existing server side validation attributes and use them to implement client-side validation. We do not have to write a single line of custom JavaScript code. All we need is the above 3 script files in the order specified.

Unobtrusive validation not working in ASP.NET Core

If the unobtrusive client-side validation is not working, make sure you check the following.

Make sure browser support for JavaScript is not disabled

Make sure the 3 client-side validation libraries are loaded in the order specified

Make sure these validation libraries are loaded for the environment you are testing against. Development, Staging, Production etc.



-------------------------------------------------------------------------------------------------------------------------------------------------------
																ASP NET core remote validation


Remote validation allows a controller action method to be called using client side script. This is very useful when you want to call a server side method without a full page post back.

Remote validation example

Checking, if the provided email is already taken by another user can only be done on the server. The following IsEmailInUse() controller action method checks if the provided email is in use.

[AcceptVerbs("Get", "Post")]
[AllowAnonymous]
public async Task[IActionResult] IsEmailInUse(string email)
{
    var user = await userManager.FindByEmailAsync(email);
            
    if (user == null)
    {
        return Json(true);
    }
    else
    {
        return Json($"Email {email} is already in use.");
    }
}

This method should respond to both HTTP GET and POST. This is the reason we specified both the HTTP verbs (Get and Post) using [AcceptVerbs] attribute.
ASP.NET Core MVC uses jQuery remote() method which in turn issues an AJAX call to invoke the server side method. 
The jQuery remote() method expects a JSON response, this is the reason we are returing JSON response from the server-side method (IsEmailInUse)

ASP.NET core remote attribute

The following is the model class for the User Registration View. Notice, we have decorated the Email property with the [Remote] attribute pointing it to the action method that should be invoked when the email value changes.

public class RegisterViewModel
{
    [Required]
    [EmailAddress]
    [Remote(action: "IsEmailInUse", controller: "Account")]
    public string Email { get; set; }

    // Other properties
}

ASP.NET core remote validation not working

The following 3 client-side libararies are required in the order specified for the remote validation to work. If any of them are missing or not loaded in the order specified, remote validation will not work.

[script src="~/lib/jquery/jquery.js"][/script]
[script src="~/lib/jquery-validate/jquery.validate.js"][/script]
[script src="~/lib/jquery-validation-unobtrusive/jquery.validate.unobtrusive.js"][/script]

------------------------------------------------------------------------------------------------------------------------------------------------------------

															Custom validation attribute in asp net core

ASP.NET Core built-in attributes

For most use cases asp.net core has several built-in attributes for model validation. We discussed some of these attributes in Parts 42 and 43 of ASP.NET Core tutorial. Some of the built-in attributes are listed below.

Required
Range
StringLength
Compare
Regular Expression

Custom Attribute in ASP.NET Core

If you have a complex validation requirement that you cannot implement using the built-in attributes, you can create a custom validation attribute and reuse it in your project or even in multiple projects if you create it in a separate class library project.

Custom Validation Attribute Example

On a new user registration page, we want to only allow email address where the domain name is pragimtech.com. If any other domain name is used, we want to display a validation error. We could achieve this using the built-in regular expression validator, but let's create a custom validator.

ValidationAttribute class in ASP.NET Core

To create a custom validation attribute, create a class that derives from the built-in abstract ValidationAttribute class and override IsValid() method.

public class ValidEmailDomainAttribute : ValidationAttribute
{
    private readonly string allowedDomain;
        
    public ValidEmailDomainAttribute(string allowedDomain)
    {
        this.allowedDomain = allowedDomain;
    }
        
    public override bool IsValid(object value)
    {
        string[] strings = value.ToString().Split('@');
        return strings[1].ToUpper() == allowedDomain.ToUpper();
    }
}

Using the Custom Validation Attribute

public class RegisterViewModel
{
    [ValidEmailDomain(allowedDomain: "pragimtech.com", 
        ErrorMessage ="Email domain must be pragimtech.com")]
    public string Email { get; set; }

    // Other Properties
}

Use the custom validation attribute just like any other built-in validation attribute.
Email property is decorated with ValidEmailDomain attribute which is our custom validation attribute.
AllowedDomain property specifies the email domain that we want to validate against.
ErrorMessage property specifies the error message that should be displayed if the validation failes.
The ErrorMessage property is inherited from the built-in base class ValidationAttribute.
The validation error message is then picked up and displayed by the built-in validation tag helper.


-----------------------------------------------------------------------------------------------------------------------------------------------
															Extend IdentityUser in ASP NET Core

Why should we extend IdentityUser class

The built-in IdentityUser class has very limited set of properties like Id, Username, Email, PasswordHash etc. 

What if I want to store additional data about the user like Gender, City, Country etc. The built-in IdentityUser class does not have these properties. To store custom user data like Gender, City, Country etc, extend the IdentityUser class.

Extend IdentityUser Class

You can name the class that extends the IdentityUser class anything you want, but it is customary to name it ApplicationUser. In the example below, ApplicationUser class extends the IdentityUser class. We have included just one custom property City, but you can include as many properties as you want.

public class ApplicationUser : IdentityUser
{
    public string City { get; set; }
}

Find all references of IdentityUser class and replace it with our custom ApplicationUser class. 

Specify ApplicationUser class as the generic argument for the IdentityDbContext class

This is how the IdentityDbContext class knows it has to work with our custom user class (in this case ApplicationUser class) instead of the default built-in IdentityUser class. 

public class AppDbContext : IdentityDbContext[ApplicationUser]
{
    public AppDbContext(DbContextOptions[AppDbContext] options)
        : base(options)
    {
    }

    public DbSet[Employee] Employees { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Seed();
    }
}

Generate a new migration to add columns to AspNetUsers table

Add-Migration Extend_IdentityUser

Next, apply the migration to the database using the following command

Update-Database

Extending IdentityUser - Add-Migration Not Working 

If ApplicationUser class (the class that extends IdentityUser class) is not specified as the generic argument for IdentityDbContext class, Add-Migration command does not work. It does not generate the required migration code to add the adiitional columns to the AspNetUsers identity table.

To fix this, specify ApplicationUser class as the generic argument for IdentityDbContext class.

If you get the following exception, the most likely cause is somewhere with in your application you are still using IdentityUser class instead of the ApplicationUser class.
No service for type 'Microsoft.AspNetCore.Identity.SignInManager`1[Microsoft.AspNetCore.Identity.IdentityUser]' has been registered.

In Visual Studio, search for IdentityUser class throughout your application using CTRL + SHIFT + F

Replace IdentityUser class with ApplicationUser class and rerun the project.

Storing custom data in AspNetUsers table
