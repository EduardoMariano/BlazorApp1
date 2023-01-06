using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.VisualBasic;
using static Duende.IdentityServer.Models.IdentityResources;
using BlazorApp1.Server.Models;
using Microsoft.AspNetCore.Components.Authorization;
using BlazorApp1.Server.Data;

namespace BlazorApp1.Server.Extensions
{
    public static class OqtaneSiteAuthenticationBuilderExtensions
    {        
        internal static async Task OnTokenValidated(TokenValidatedContext arg)
        {
            ////arg.Principal.Identity.IsAuthenticated = true;
            //var idClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:IdentifierClaimType", "");
            //var id = arg.Principal.FindFirstValue(idClaimType);
            //var emailClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:EmailClaimType", "");
            //var email = arg.Principal.FindFirstValue(emailClaimType);
            //var claims = string.Join(", ", arg.Principal.Claims.Select(item => item.Type).ToArray());
            //var identity = await ValidateUser(email, id, claims, arg.HttpContext);
            //if (!string.IsNullOrEmpty(arg.HttpContext.GetSiteSettings().GetValue("ExternalLogin:RoleClaimType", "")))
            //{
            //    foreach (var claim in arg.Principal.Claims.Where(item => item.Type == ClaimTypes.Role))
            //    {
            //        if (!identity.Claims.Any(item => item.Type == ClaimTypes.Role && item.Value == claim.Value))
            //        {
            //            identity.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
            //        }
            //    }
            //}

            //identity.AddClaim(new Claim("access_token", arg.SecurityToken.RawData));
            //arg.Principal = new ClaimsPrincipal(identity);
            ////arg.Principal.AddIdentity(identity);
            ////identity.AddClaim(new Claim("access_token", arg.SecurityToken.RawData));
            ////identity.Label = "Success";
            ////arg.HttpContext.User = new ClaimsPrincipal(identity);
            ////arg.Principal = new ClaimsPrincipal(identity);            
        }

        //private static Task OnTokenValidated(TokenValidatedContext context)
        //{
        //    // OpenID Connect

        //    //var idClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:IdentifierClaimType", "");
        //    //    var id = context.Principal.FindFirstValue(idClaimType);
        //    //var emailClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:EmailClaimType", "");
        //    //    var email = context.Principal.FindFirstValue(emailClaimType);
        //    //    var claims = string.Join(", ", context.Principal.Claims.Select(item => item.Type).ToArray());

        //    //    // validate user
        //    //    var identity = ValidateUser(email, id, claims, context.HttpContext);
        //    ClaimsIdentity identity = new ClaimsIdentity("Identity.Application");
        //    identity.AddClaim(new Claim(ClaimTypes.Name, "Identity.Application"));
        //    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Identity.Application".ToString()));
        //    identity.AddClaim(new Claim("sitekey", "Identity.Application"));
        //    identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //    var principal = new ClaimsPrincipal(identity);
        //    context.Principal = principal;

        //    //identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //    //context.Principal = new ClaimsPrincipal(identity);
        //    //if (identity.Label == ExternalLoginStatus.Success)
        //    //{
        //    //    // external roles
        //    //    if (!string.IsNullOrEmpty(context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:RoleClaimType", "")))
        //    //    {
        //    //        foreach (var claim in context.Principal.Claims.Where(item => item.Type == ClaimTypes.Role))
        //    //        {
        //    //            if (!identity.Claims.Any(item => item.Type == ClaimTypes.Role && item.Value == claim.Value))
        //    //            {
        //    //                identity.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
        //    //            }
        //    //        }
        //    //    }

        //    //    identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //    //    context.Principal = new ClaimsPrincipal(identity);
        //    //}
        //    //else
        //    //{
        //    //    // redirect to login page and pass status
        //    //    context.Response.Redirect(Utilities.TenantUrl(context.HttpContext.GetAlias(), $"/login?status={identity.Label}&returnurl={context.Properties.RedirectUri}"), true);
        //    //    context.HandleResponse();
        //    //}
        //    //throw new NotImplementedException();

        //}


        //private static Task OnTokenValidated(TokenValidatedContext context)
        //{
        //    // OpenID Connect
        //    var idClaimType = "";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:IdentifierClaimType", "");
        //    var id = context.Principal.FindFirstValue(idClaimType);
        //    var emailClaimType = "";// context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:EmailClaimType", "");
        //    var email = context.Principal.FindFirstValue(emailClaimType);
        //    var claims = string.Join(", ", context.Principal.Claims.Select(item => item.Type).ToArray());

        //    // validate user
        //    var identity = await ValidateUser(email, id, claims, context.HttpContext);
        //    identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //    context.Principal = new ClaimsPrincipal(identity);
        //    //if (identity.Label == ExternalLoginStatus.Success)
        //    //{
        //    //    // external roles
        //    //    if (!string.IsNullOrEmpty(context.HttpContext.GetSiteSettings().GetValue("ExternalLogin:RoleClaimType", "")))
        //    //    {
        //    //        foreach (var claim in context.Principal.Claims.Where(item => item.Type == ClaimTypes.Role))
        //    //        {
        //    //            if (!identity.Claims.Any(item => item.Type == ClaimTypes.Role && item.Value == claim.Value))
        //    //            {
        //    //                identity.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
        //    //            }
        //    //        }
        //    //    }

        //    //    identity.AddClaim(new Claim("access_token", context.SecurityToken.RawData));
        //    //    context.Principal = new ClaimsPrincipal(identity);
        //    //}
        //    //else
        //    //{
        //    //    // redirect to login page and pass status
        //    //    context.Response.Redirect(Utilities.TenantUrl(context.HttpContext.GetAlias(), $"/login?status={identity.Label}&returnurl={context.Properties.RedirectUri}"), true);
        //    //    context.HandleResponse();
        //    //}
        //}

        private static async Task<ClaimsIdentity> ValidateUser(string email, string id, string claims, HttpContext httpContext)
        {            
            ClaimsIdentity identity = new ClaimsIdentity("Identity.Application");
            if (!string.IsNullOrEmpty(id))
            {
                // verify if external user is already registered for this site
                var _identityUserManager = httpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                var identityuser = await _identityUserManager.FindByLoginAsync("oidc-idserver", id);                
                identity.AddClaim(new Claim(ClaimTypes.Name, identityuser.UserName));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, identityuser.Id.ToString()));
                identity.AddClaim(new Claim("sitekey", "1:1"));
                //user = identityuser;
                //user = _users.  .GetUser(identityuser.UserName);
                //// manage user
                //if (user != null)
                //{
                //    // create claims identity
                //    identity.AddClaim(new Claim(ClaimTypes.Name, "Identity.Application"));
                //    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Identity.Application".ToString()));
                //    identity.AddClaim(new Claim("sitekey", "Identity.Application"));



                //}
            }
            //ClaimsIdentity identity = new ClaimsIdentity("Identity.Application");
            // use identity.Label as a temporary location to store validation status information

            //var providerType = httpContext.GetSiteSettings().GetValue("ExternalLogin:ProviderType", "");
            //var providerName = httpContext.GetSiteSettings().GetValue("ExternalLogin:ProviderName", "");
            //var _identityUserManager = httpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            //var identityuser = await _identityUserManager.FindByLoginAsync(providerType + ":", id);
            //var alias = httpContext.GetAlias();
            //var _users = httpContext.RequestServices.GetRequiredService<IUserRepository>();
            //User user = null;

            //if (!string.IsNullOrEmpty(id))
            //{
            //    // verify if external user is already registered for this site
            //    var _identityUserManager = httpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            //    var identityuser = await _identityUserManager.FindByLoginAsync(providerType + ":" + alias.SiteId.ToString(), id);
            //    if (identityuser != null)
            //    {
            //        user = _users.GetUser(identityuser.UserName);
            //    }
            //    else
            //    {
            //        if (EmailValid(email, httpContext.GetSiteSettings().GetValue("ExternalLogin:DomainFilter", "")))
            //        {
            //            bool duplicates = false;
            //            try
            //            {
            //                identityuser = await _identityUserManager.FindByEmailAsync(email);
            //            }
            //            catch
            //            {
            //                // FindByEmailAsync will throw an error if the email matches multiple user accounts
            //                duplicates = true;
            //            }
            //            if (identityuser == null)
            //            {
            //                if (duplicates)
            //                {
            //                    identity.Label = ExternalLoginStatus.DuplicateEmail;
            //                    _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "Multiple Users Exist With Email Address {Email}. Login Denied.", email);
            //                }
            //                else
            //                {
            //                    if (bool.Parse(httpContext.GetSiteSettings().GetValue("ExternalLogin:CreateUsers", "true")))
            //                    {
            //                        identityuser = new IdentityUser();
            //                        identityuser.UserName = email;
            //                        identityuser.Email = email;
            //                        identityuser.EmailConfirmed = true;
            //                        var result = await _identityUserManager.CreateAsync(identityuser, DateTime.UtcNow.ToString("yyyy-MMM-dd-HH-mm-ss"));
            //                        if (result.Succeeded)
            //                        {
            //                            user = new User
            //                            {
            //                                SiteId = alias.SiteId,
            //                                Username = email,
            //                                DisplayName = email,
            //                                Email = email,
            //                                LastLoginOn = null,
            //                                LastIPAddress = ""
            //                            };
            //                            user = _users.AddUser(user);

            //                            if (user != null)
            //                            {
            //                                var _notifications = httpContext.RequestServices.GetRequiredService<INotificationRepository>();
            //                                string url = httpContext.Request.Scheme + "://" + alias.Name;
            //                                string body = "You Recently Used An External Account To Sign In To Our Site.\n\n" + url + "\n\nThank You!";
            //                                var notification = new Notification(user.SiteId, user, "User Account Notification", body);
            //                                _notifications.AddNotification(notification);

            //                                // add user login
            //                                await _identityUserManager.AddLoginAsync(identityuser, new UserLoginInfo(providerType + ":" + alias.SiteId.ToString(), id, providerName));

            //                                _logger.Log(user.SiteId, LogLevel.Information, "ExternalLogin", Enums.LogFunction.Create, "User Added {User}", user);
            //                            }
            //                            else
            //                            {
            //                                identity.Label = ExternalLoginStatus.UserNotCreated;
            //                                _logger.Log(user.SiteId, LogLevel.Error, "ExternalLogin", Enums.LogFunction.Create, "Unable To Add User {Email}", email);
            //                            }
            //                        }
            //                        else
            //                        {
            //                            identity.Label = ExternalLoginStatus.UserNotCreated;
            //                            _logger.Log(user.SiteId, LogLevel.Error, "ExternalLogin", Enums.LogFunction.Create, "Unable To Add Identity User {Email} {Error}", email, result.Errors.ToString());
            //                        }
            //                    }
            //                    else
            //                    {
            //                        identity.Label = ExternalLoginStatus.UserDoesNotExist;
            //                        _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "Creation Of New Users Is Disabled For This Site. User With Email Address {Email} Will First Need To Be Registered On The Site.", email);
            //                    }
            //                }
            //            }
            //            else
            //            {
            //                var logins = await _identityUserManager.GetLoginsAsync(identityuser);
            //                var login = logins.FirstOrDefault(item => item.LoginProvider == (providerType + ":" + alias.SiteId.ToString()));
            //                if (login == null)
            //                {
            //                    // new external login using existing user account - verification required
            //                    var _notifications = httpContext.RequestServices.GetRequiredService<INotificationRepository>();
            //                    string token = await _identityUserManager.GenerateEmailConfirmationTokenAsync(identityuser);
            //                    string url = httpContext.Request.Scheme + "://" + alias.Name;
            //                    url += $"/login?name={identityuser.UserName}&token={WebUtility.UrlEncode(token)}&key={WebUtility.UrlEncode(id)}";
            //                    string body = $"You Recently Signed In To Our Site With {providerName} Using The Email Address {email}. ";
            //                    body += "In Order To Complete The Linkage Of Your User Account Please Click The Link Displayed Below:\n\n" + url + "\n\nThank You!";
            //                    var notification = new Notification(alias.SiteId, email, email, "External Login Linkage", body);
            //                    _notifications.AddNotification(notification);

            //                    identity.Label = ExternalLoginStatus.VerificationRequired;
            //                    _logger.Log(alias.SiteId, LogLevel.Information, "ExternalLogin", Enums.LogFunction.Create, "External Login Linkage Verification For Provider {Provider} Sent To {Email}", providerName, email);
            //                }
            //                else
            //                {
            //                    // provider keys do not match
            //                    identity.Label = ExternalLoginStatus.ProviderKeyMismatch;
            //                    _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "Provider Key Does Not Match For User {Username}. Login Denied.", identityuser.UserName);
            //                }
            //            }
            //        }
            //        else // email invalid
            //        {
            //            identity.Label = ExternalLoginStatus.InvalidEmail;
            //            if (!string.IsNullOrEmpty(email))
            //            {
            //                _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "The Email Address {Email} Is Invalid Or Does Not Match The Domain Filter Criteria. Login Denied.", email);
            //            }
            //            else
            //            {
            //                _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "Provider Did Not Return An Email Address To Uniquely Identify The User. The Email Claim Specified Was {EmailCLaimType} And Actual Claim Types Are {Claims}. Login Denied.", httpContext.GetSiteSettings().GetValue("ExternalLogin:EmailClaimType", ""), claims);
            //            }
            //        }
            //    }

            //    // manage user
            //    if (user != null)
            //    {
            //        // create claims identity
            //        var _userRoles = httpContext.RequestServices.GetRequiredService<IUserRoleRepository>();
            //        identity = UserSecurity.CreateClaimsIdentity(alias, user, _userRoles.GetUserRoles(user.UserId, user.SiteId).ToList());
            //        identity.Label = ExternalLoginStatus.Success;

            //        // update user
            //        user.LastLoginOn = DateTime.UtcNow;
            //        user.LastIPAddress = httpContext.Connection.RemoteIpAddress.ToString();
            //        _users.UpdateUser(user);
            //        _logger.Log(LogLevel.Information, "ExternalLogin", Enums.LogFunction.Security, "External User Login Successful For {Username} Using Provider {Provider}", user.Username, providerName);
            //    }
            //}
            //else // id invalid
            //{
            //    _logger.Log(LogLevel.Error, "ExternalLogin", Enums.LogFunction.Security, "Provider Did Not Return An Identifier To Uniquely Identify The User. The Identifier Claim Specified Was {IdentifierCLaimType} And Actual Claim Types Are {Claims}. Login Denied.", httpContext.GetSiteSettings().GetValue("ExternalLogin:IdentifierClaimType", ""), claims);
            //}

            return identity;
        }
    }
}
