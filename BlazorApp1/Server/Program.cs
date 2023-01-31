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
using System.IdentityModel.Tokens.Jwt;
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
    .AddApiAuthorization<ApplicationUser, ApplicationDbContext>(options => {
        options.IdentityResources["openid"].UserClaims.Add("name");
        options.ApiResources.Single().UserClaims.Add("name");
        options.IdentityResources["openid"].UserClaims.Add("role");
        options.ApiResources.Single().UserClaims.Add("role");
        options.IdentityResources["openid"].UserClaims.Add("IsUserAdmin");
        options.ApiResources.Single().UserClaims.Add("IsUserAdmin");
        options.IdentityResources["openid"].UserClaims.Add("AvailableButtonCounter");
        options.ApiResources.Single().UserClaims.Add("AvailableButtonCounter");
        options.IdentityResources["openid"].UserClaims.Add("AvailableButtonSort");
        options.ApiResources.Single().UserClaims.Add("AvailableButtonSort");
    });
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Remove("role");

builder.Services.AddAuthentication()
    .AddIdentityServerJwt();


List<string> rolesToAvailableButtonSort = new List<string>();
rolesToAvailableButtonSort.Add("Admin");
rolesToAvailableButtonSort.Add("Vendor");
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("IsUserAdmin", policy =>
        policy.RequireRole("Admin").RequireClaim("IsUserAdmin", "true"));
    options.AddPolicy("AvailableButtonCounter", policy =>
        policy.RequireRole("User").RequireClaim("AvailableButtonCounter", "true"));
    options.AddPolicy("AvailableButtonSort", policy =>
        policy.RequireRole(rolesToAvailableButtonSort));
});

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

foreach (var item in builder.Configuration.GetSection("IntegrationOpenIdConnect").Get<List<IdentityProvider>>())
{
    
    builder.Services.AddAuthentication().AddOpenIdConnect(item.AuthenticationScheme, item.DisplayName, o =>
    {      
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
    }
    );    
}

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
app.UseAuthentication();
app.UseAuthorization();


app.MapRazorPages();
app.MapControllers();
app.MapFallbackToFile("index.html");
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");


app.Run();
