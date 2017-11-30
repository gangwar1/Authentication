using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using System.Net.Http.Formatting;

namespace WebApplication_Auth
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            //// Web API configuration and services
            //// Configure Web API to use only bearer token authentication.
            //config.SuppressDefaultHostAuthentication();
            //config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            //// Web API routes
            //config.MapHttpAttributeRoutes();

            //config.Routes.MapHttpRoute(
            //    name: "DefaultApi",
            //    routeTemplate: "api/{controller}/{id}",
            //    defaults: new { id = RouteParameter.Optional }
            //);

            //config.EnableCors();
            config.MapHttpAttributeRoutes();
            var jsonFormatter = config.Formatters.OfType<JsonMediaTypeFormatter>().First();

            ////Enable CORS
            //var corsAttr = new EnableCorsAttribute("*", "*", "*");
            //config.EnableCors(corsAttr);

            //// Web API configuration and services
            //config.Formatters.XmlFormatter.AddUriPathExtensionMapping("xml", XmlMediaTypeFormatter.DefaultMediaType);
            //config.Formatters.JsonFormatter.AddUriPathExtensionMapping("json", JsonMediaTypeFormatter.DefaultMediaType);

            //var jsonFormatter = config.Formatters.OfType<JsonMediaTypeFormatter>().FirstOrDefault();
            //if (jsonFormatter != null)
            //{
            //    jsonFormatter.Indent = true;
            //    jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            //}

            //config.Formatters.Remove(config.Formatters.XmlFormatter);

            //// Web API routes
            //config.MapHttpAttributeRoutes();

            //config.Routes.MapHttpRoute("DefaultApi", "{controller}/{id}", new { id = RouteParameter.Optional }
            //    );

            //config.Filters.Add(new RevFlowException());
        }
    }
}
