using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace WebApplication_Auth.Providers
{
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        private string spareTokenGuid = "43f26de6-80e4-4729-870f-9ab79c34e2b0";
        private bool spareTokenExists = false;
        private ConcurrentDictionary<string, AuthenticationTicket> _refreshTokens = new ConcurrentDictionary<string, AuthenticationTicket>();
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// This method will be used to set refresh token and add authentication ticket 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {

            var guid = Guid.NewGuid().ToString();
            #region Add Extra Token If Failed
            AuthenticationTicket ticket;
            if (!spareTokenExists || !_refreshTokens.TryGetValue(spareTokenGuid, out ticket))
            {
                var spareRefreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary);
                var spareRefreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, spareRefreshTokenProperties);
                spareTokenExists = _refreshTokens.TryAdd(spareTokenGuid, spareRefreshTokenTicket);
              //  RevFlowLogging.LogInfo("Spare token is set in the Dictionary first time during login count is = " + _refreshTokens.Count);
            }
            #endregion
            // copy all properties and set the desired lifetime of refresh token  
            var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary);
            var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);
            _refreshTokens.TryAdd(guid, refreshTokenTicket);
            // consider storing only the hash of the handle  
            context.SetToken(guid);
            return Task.FromResult<object>(null);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// This method will be used to set ticket on the  basis of refresh token
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
    #pragma warning disable 1998
        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;
            if (_refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
            }
            else
            {
                var spareToken = _refreshTokens.TryGetValue(spareTokenGuid, out ticket);
                if (spareToken)
                {
                    //RevFlowLogging.LogInfo("Spare token Used ");
                    //Token does not found in the dictionary and spare  token is set                                        
                    ticket.Properties.IssuedUtc = DateTime.Now;
                    ticket.Properties.ExpiresUtc = DateTime.Now.AddMinutes(Convert.ToInt32(ConfigurationManager.AppSettings["minutesInterval"].ToString()));
                    context.SetTicket(ticket);
                }
                else
                {
                  //  RevFlowLogging.LogInfo("Both Spare token and refresh token not found in the dictionary object the Dictionary count is = " + _refreshTokens.Count);
                    throw new Exception("Ticket does not exist");
                }

            }
        }

    }
}