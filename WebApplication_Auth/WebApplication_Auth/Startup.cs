using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using System.Web.Mvc;
using Microsoft.Owin.Security.OAuth;
using WebApplication_Auth.Providers;
using System.Configuration;
using System.Web.Cors;
using Microsoft.Owin.Cors;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(WebApplication_Auth.Startup))]

namespace WebApplication_Auth
{
    public partial class Startup
    {
        public OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            app.UseCors(EnableCors());
            app.UseWebApi(config);

            ConfigureOAuth(app);
            //RevFlowLogging.Configure(true);
            WebApiConfig.Register(config);
        }

        private CorsOptions EnableCors()
        {
            var corsPolicy = new CorsPolicy
            {
                AllowAnyMethod = true,
                AllowAnyHeader = true,
                AllowAnyOrigin = true,
                PreflightMaxAge = 864000
            };
            var origins = ConfigurationManager.AppSettings["CorsOriginsSettingKey"];
            if (origins != null)
            {
                foreach (var origin in origins.Split(';'))
                {
                    corsPolicy.Origins.Add(origin);
                }
            }
            else
            {
                corsPolicy.AllowAnyOrigin = true;
            }

            var corsOptions = new CorsOptions
            {
                PolicyProvider = new CorsPolicyProvider
                {
                    PolicyResolver = context => Task.FromResult(corsPolicy)
                }
            };
            return corsOptions;
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(Convert.ToInt32(ConfigurationManager.AppSettings["minutesInterval"].ToString())),
                Provider = new AuthorizationServerProvider(),
                RefreshTokenProvider = new RefreshTokenProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);
        }
    }
}
