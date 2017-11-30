using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using System.Configuration;

namespace WebApplication_Auth.Providers
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {/// <summary>
     /// Called to validate that the origin of the request is a registered "client_id", and that the correct credentials for that client are
     /// present on the request. If the web application accepts Basic authentication credentials,
     /// context.TryGetBasicCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request header. If the web
     /// application accepts "client_id" and "client_secret" as form encoded POST parameters,
     /// context.TryGetFormCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request body.
     /// If context.Validated is not called the request will not proceed further.
     /// </summary>
     /// <param name="context">The context of the event carries information in and results out.</param>
     /// <returns>
     /// Task to enable asynchronous execution
     /// </returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            if (context.Parameters.Count() > 0)
            {
                string info = string.Empty;
                info = context.Parameters.Where(f => f.Key == "uid").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("UserID", info);
                info = context.Parameters.Where(f => f.Key == "companyid").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("CompanyID", info);
                info = context.Parameters.Where(f => f.Key == "userTypeId").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("UserTypeId", info);
                info = context.Parameters.Where(f => f.Key == "userTypeR3Id").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("UserTypeR3Id", info);
                info = context.Parameters.Where(f => f.Key == "providerId").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("ProviderId", info);
                info = context.Parameters.Where(f => f.Key == "providerTypeId").Select(f => f.Value).SingleOrDefault()[0];
                context.OwinContext.Set<string>("ProviderTypeId", info);


            }

            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "password". This occurs when the user has provided name and password
        /// credentials directly into the client application's user interface, and the client application is using those to acquire an "access_token" and
        /// optional "refresh_token". If the web application supports the
        /// resource owner credentials grant type it must validate the context.Username and context.Password as appropriate. To issue an
        /// access token the context.Validated must be called with a new ticket containing the claims about the resource owner which should be associated
        /// with the access token. The application should take appropriate measures to ensure that the endpoint isn’t abused by malicious callers.
        /// The default behavior is to reject this grant type.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>
        /// Task to enable asynchronous execution
        /// </returns>
#pragma warning disable 1998
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            //if (allowedOrigin == null) allowedOrigin = "*";
            //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });
            //Find userid
            string uid = context.OwinContext.Get<string>("UserID");
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("User", context.UserName));
            identity.AddClaim(new Claim("UserID", uid));
            identity.AddClaim(new Claim("CompanyID", context.OwinContext.Get<string>("CompanyID")));
            identity.AddClaim(new Claim("UserTypeId", context.OwinContext.Get<string>("UserTypeId")));
            identity.AddClaim(new Claim("UserTypeR3Id", context.OwinContext.Get<string>("UserTypeR3Id")));
            identity.AddClaim(new Claim("ProviderId", context.OwinContext.Get<string>("ProviderId")));
            identity.AddClaim(new Claim("ProviderTypeId", context.OwinContext.Get<string>("ProviderTypeId")));
            //Generate claim information         
            var authenticationProperties = new AuthenticationProperties(new Dictionary<string, string> {
                {
                    "as:client_id",(context.ClientId==null)?string.Empty:context.ClientId
                },
                {
                    "userName",context.UserName
                }
            })
            {

                AllowRefresh = true
            };
            var ticket = new AuthenticationTicket(identity, authenticationProperties);
            context.Validated(ticket);
        }
        /// <summary>
        /// this method will be used to add ticket when refresh token is called
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            //if (string.IsNullOrEmpty(context.OwinContext.Response.Headers.Get("Access-Control-Allow-Origin")))
            //{
            //    var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            //    if (allowedOrigin == null) allowedOrigin = "*";
            //    context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });
            //}
            // Change authentication ticket for refresh token requests  

            //Validate the tikcet 
            string uid = context.OwinContext.Get<string>("UserID");
            //case when idenity is different from token
            if (context.Ticket.Identity.Claims.Count(t => t.Type == "UserID" && t.Value == uid) == 0)
            {
               // RevFlowLogging.LogInfo(" GrantRefreshToken identity Changes ");
               // RevFlowLogging.LogInfo("Incorrect Identity : " + uid);
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                var properties = context.Ticket.Properties;
                foreach (var item in context.Ticket.Identity.Claims)
                {
                    if (context.OwinContext.Get<string>(item.Type) != null)
                        identity.AddClaim(new Claim(item.Type, context.OwinContext.Get<string>(item.Type)));
                    if (item.Type.Equals("UserID", StringComparison.InvariantCultureIgnoreCase)) { }
                      //  RevFlowLogging.LogInfo("Identity Old : " + uid + " Identity New :" + context.OwinContext.Get<string>(item.Type));

                }
                //Create new ticket
                var newTicket = new AuthenticationTicket(identity, properties);
                context.Validated(newTicket);
            }
            else
            {
                context.Validated(context.Ticket);
            }

            return Task.FromResult<object>(null);
        }
        /// <summary>
        /// This method will be used to add additional response parameter in the context
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            context.AdditionalResponseParameters.Add("MinutesInterval", (Convert.ToInt32(ConfigurationManager.AppSettings["minutesInterval"].ToString()) * 60));
            return Task.FromResult<object>(null);
        }
    }
}