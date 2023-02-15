using BlazorApp1.Server.Data;
using BlazorApp1.Server.Models;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
//builder.Services.AddDatabaseDeveloperPageExceptionFilter();


builder.Services.AddDefaultIdentity<ApplicationUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();
//List<Client> Clients =
//    new List<Client>
//    {
//        new Client
//        {
//            ClientId = "3X=nNv?Sgu$S",

//            // no interactive user, use the clientid/secret for authentication
//            AllowedGrantTypes = GrantTypes.ClientCredentials,

//            // secret for authentication
//            ClientSecrets =
//            {
//                new Secret("1554db43-3015-47a8-a748-55bd76b6af48".Sha256())
//            },

//            // scopes that client has access to
//            AllowedScopes = { "api1" }
//        }
//    };
//List<ApiResource> ApiScopes =
//        new List<ApiResource>
//        {
//            new ApiResource("api1", "My API")
//        };
//List<Client> clientList = new List<Client>() { new Client
//        {
//            ClientName = "Client Application2",
//            ClientId = "3X=nNv?Sgu$S",
//            AllowedGrantTypes = GrantTypes.ClientCredentials,
//            ClientSecrets = { new Secret("1554db43-3015-47a8-a748-55bd76b6af48".Sha256())},
//            AllowedScopes = { "app.api.weather" }
//        } };
//List<ApiResource> Apis = new List<ApiResource>() { new ApiResource("app.api.weather", "Weather Apis") };
//builder.Services.AddAuthentication().AddJwtBearer(options =>
//{
//    options.Authority = "https://localhost:7123";
//    options.Audience = "app.api.weather";
//});


builder.Services.AddIdentityServer()
//    .AddDeveloperSigningCredential()
//.AddInMemoryApiResources(ApiScopes)
//.AddInMemoryClients(Clients)
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
        //options.Clients.Add(new Client
        //{
        //    ClientName = "Client Application2",
        //    ClientId = "3X=nNv?Sgu$S",
        //    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
        //    ClientSecrets = { new Secret("1554db43-3015-47a8-a748-55bd76b6af48".Sha256()),

        //    }
        //});
        options.ApiScopes.Add(new ApiScope(name: "api1",
    displayName: "My API"));
        options.Clients.Add(new Client
        {
            ClientName = "Client Application2",
            ClientId = "3X=nNv?Sgu$S",
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            ClientSecrets = { new Secret("1554db43-3015-47a8-a748-55bd76b6af48".Sha256())},
            AlwaysSendClientClaims= true
            ,AllowedScopes = { "api1" },
            Claims = new List<ClientClaim>
                    {
                        new ClientClaim("scope", "api1"),                       
                    }
        });
        //options.ApiResources.Add(new ApiResource("api1", "My API"));
    });
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Remove("role");
builder.Services.AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = "https://localhost:7070";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false
                };
            });
builder.Services.AddAuthentication()
    .AddIdentityServerJwt();


List<string> rolesToAvailableButtonSort = new List<string>();
rolesToAvailableButtonSort.Add("Admin");
rolesToAvailableButtonSort.Add("User");
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

foreach (var item in builder.Configuration.GetSection("IntegrationOpenIdConnect").Get<List<BlazorApp1.Shared.IdentityProvider>>())
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
