using BlazorApp1.Server.Data;
using BlazorApp1.Server.Extensions;
using BlazorApp1.Server.Models;
using BlazorApp1.Shared;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualBasic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using static System.Formats.Asn1.AsnWriter;

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();


builder.Services.AddDefaultIdentity<ApplicationUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddIdentityServer()
    .AddApiAuthorization<ApplicationUser, ApplicationDbContext>();

//builder.Services.AddAuthentication()
//    .AddIdentityServerJwt();

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
//}).AddCookie();

foreach (var item in builder.Configuration.GetSection("IntegrationOpenIdConnect").Get<List<IdentityProvider>>())
{
    
    builder.Services.AddAuthentication().AddOpenIdConnect(item.AuthenticationScheme, item.DisplayName, o =>
    {
        //o.SignInScheme = "Identity.Application";
        //o.SaveTokens = false;

        //o.GetClaimsFromUserInfoEndpoint = true;
        //o.ResponseType = OpenIdConnectResponseType.Code; // authorization code flow
        //o.ResponseMode = OpenIdConnectResponseMode.FormPost; // recommended as most secure

        //// cookie config is required to avoid Correlation Failed errors
        //o.NonceCookie.SameSite = SameSiteMode.Unspecified;
        //o.CorrelationCookie.SameSite = SameSiteMode.Unspecified;

        o.MetadataAddress = item.MetadataAddress;
        o.ClientId = item.ClientId;
        o.ClientSecret = item.ClientSecret;
        o.ResponseType = "code";
        o.GetClaimsFromUserInfoEndpoint = true;
        o.CallbackPath = new PathString(item.CallbackPath);
        o.SignedOutCallbackPath = new PathString(item.SignedOutCallbackPath);

        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("email");


        //o.Events = new OpenIdConnectEvents
        //{
        //    OnTokenValidated = async context =>
        //    {
        //        ClaimsIdentity identity = new ClaimsIdentity("Identity.Application");
        //        identity.AddClaim(new Claim(ClaimTypes.Name, "Identity.Application"));
        //        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Identity.Application".ToString()));
        //        identity.AddClaim(new Claim("sitekey", "Identity.Application"));
        //        identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //        context.Principal = new ClaimsPrincipal(identity);                
        //    }
        //};

        //o.Events = new OpenIdConnectEvents
        //{

        ////OnTokenValidated = async ctx =>
        ////{
        ////    //Get user's immutable object id from claims that came from Azure AD
        ////    string oid = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");

        ////    //Get EF context
        ////    var db = ctx.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();

        ////    //Check is user a super admin
        ////    bool isSuperAdmin = true;// await db..AnyAsync(a => a.UserId == oid);
        ////    if (isSuperAdmin)
        ////    {
        ////        //Add claim if they are
        ////        var claims = new List<Claim>
        ////        {
        ////            //new Claim(ClaimTypes.Role, "superadmin")
        ////            new Claim("access_token", ctx.SecurityToken.RawData)
        ////        };
        ////        var appIdentity = new ClaimsIdentity(claims, "Identity.Application");

        ////        ctx.Principal.AddIdentity(appIdentity);
        ////    }
        ////}
        // };
        o.Events.OnTokenValidated = OqtaneSiteAuthenticationBuilderExtensions.OnTokenValidated;

        //o.Events.OnAccessDenied = OnAccessDenied;
        //o.Events.OnRemoteFailure = OnRemoteFailure;
        //o.Events = new OpenIdConnectEvents
        //{
        //    OnRemoteFailure = ctx =>
        //    {
        //        ctx.Response.Redirect("/");
        //        ctx.HandleResponse();
        //        return Task.CompletedTask;
        //    },
        //    OnSignedOutCallbackRedirect = ctx =>
        //    {
        //        ctx.Response.Redirect("/");
        //        ctx.HandleResponse();
        //        return Task.CompletedTask;
        //    },
        //    OnTokenValidated = ctx =>
        //    {
        //        // Get the user's email 
        //        var email = ctx.Principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

        //        //Query the database to get the role
        //        using (var db = ctx.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>())
        //        {
        //            // Get the Users from the database, with the logged in email address (from Azure)
        //            var user = db.Users.FirstOrDefault(u => u.Email.Equals("eduardo.garcia@rd-mobile.com"));

        //            if (user != null)
        //            {
        //                //user.LastLogin = DateTime.Now;
        //                //db.SaveChanges();

        //                // Add claims
        //                var claims = new List<Claim>
        //                    {
        //                        new Claim(ClaimTypes.Role, "Administrator"),
        //                        new Claim("ConfidentialAccess", "true")
        //                        //new Claim(ClaimTypes.Expired, "false")
        //                    };

        //                // Save the claim
        //                var appIdentity = new ClaimsIdentity(claims);
        //                ctx.Principal.AddIdentity(appIdentity);
        //            }
        //            else
        //            {
        //                // Send back to Login Page (with error message, maybe?)**
        //             }
        //        }
        //        return Task.CompletedTask;
        //    },
        //};
    }
    );    
}



//.AddOpenIdConnect("oidc", "Google", o =>
//{
//    o.MetadataAddress = "https://accounts.google.com/.well-known/openid-configuration";
//    o.ClientId = "1071520588055-arr621f6gfi4r3jrcnb2mcr8led3pqts.apps.googleusercontent.com";
//    o.ClientSecret = "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";
//    o.ResponseType = "code";
//    o.GetClaimsFromUserInfoEndpoint = true;
//    o.CallbackPath = new PathString("/signin-oidc");
//    o.SignedOutCallbackPath = new PathString("/signout-oidc");
//}
//)
//.AddOpenIdConnect("oidc-idserver", "Azure AD", o =>
//{
//    o.MetadataAddress = "https://login.microsoftonline.com/edca0068-4225-4645-b0c7-b570087bdbcc/v2.0/.well-known/openid-configuration";
//    o.ClientId = "13867b89-8d4e-4b8b-a3aa-526f29268262";
//    o.ClientSecret = "WCn8Q~_HiJpIt_Mzwev0Dv3PSe5DzWtKcwlMGb-i";
//    o.ResponseType = "code";
//    o.GetClaimsFromUserInfoEndpoint = true;
//    o.CallbackPath = new PathString("/signin-oidc-az");
//    o.SignedOutCallbackPath = new PathString("/signout-oidc-az");
//}
//)
//;

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

app.UseRouting();

app.UseIdentityServer();
app.UseAuthorization();


app.MapRazorPages();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();
