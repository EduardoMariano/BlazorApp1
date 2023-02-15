using BlazorApp1.Client;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using System.Security.Claims;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddHttpClient("BlazorApp1.ServerAPI", client => client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<BaseAddressAuthorizationMessageHandler>();

// Supply HttpClient instances that include access tokens when making requests to the server project
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("BlazorApp1.ServerAPI"));
List<string> rolesToAvailableButtonSort = new List<string> ();
rolesToAvailableButtonSort.Add("Admin");
rolesToAvailableButtonSort.Add("Vendor");

builder.Services.AddAuthorizationCore(options =>
{
    options.AddPolicy("IsUserAdmin", policy =>
        policy.RequireRole("Admin").RequireClaim("IsUserAdmin", "true"));
    options.AddPolicy("AvailableButtonCounter", policy =>
        policy.RequireRole("User").RequireClaim("AvailableButtonCounter", "true"));
    options.AddPolicy("AvailableButtonSort", policy =>
        policy.RequireRole(rolesToAvailableButtonSort));
});
builder.Services.AddApiAuthorization()
                .AddAccountClaimsPrincipalFactory<RolesClaimsPrincipalFactory>();



await builder.Build().RunAsync();
