using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Http.Properties;
using System.Web.Mvc;

namespace SmartSSO.Mvc
{
    public class BaseAuthorizeAttribute: AuthorizeAttribute
    {
        public const string SessionKey = "SessionKey";
        public const string SessionUserName = "SessionUserName";

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            if (filterContext == null)
            {
                throw new ArgumentNullException("filterContext");
            }

            if (OutputCacheAttribute.IsChildActionCacheActive(filterContext))
            {
                // If a child action cache block is active, we need to fail immediately, even if authorization
                // would have succeeded. The reason is that there's no way to hook a callback to rerun
                // authorization before the fragment is served from the cache, so we can't guarantee that this
                // filter will be re-run on subsequent requests.
                //throw new InvalidOperationException(MvcResources.AuthorizeAttribute_CannotUseWithinChildActionCache);
            }

            bool skipAuthorization = filterContext.ActionDescriptor.IsDefined(typeof(AllowAnonymousAttribute), inherit: true)
                                     || filterContext.ActionDescriptor.ControllerDescriptor.IsDefined(typeof(AllowAnonymousAttribute), inherit: true);

            if (skipAuthorization)
            {
                return;
            }

            IPrincipal user = filterContext.HttpContext.User;
            if (user.Identity.IsAuthenticated)
            {
                return;
            }
            else
            {
                var cookieSessionkey = "";
                var cookieSessionUserName = "";

                //SessionKey by QueryString
                if (filterContext.HttpContext.Request.QueryString[SessionKey] != null)
                {
                    cookieSessionkey = filterContext.HttpContext.Request.QueryString[SessionKey];
                }

                //SessionUserName by QueryString
                if (filterContext.HttpContext.Request.QueryString[SessionUserName] != null)
                {
                    cookieSessionUserName = filterContext.HttpContext.Request.QueryString[SessionUserName];
                }

                if (string.IsNullOrEmpty(cookieSessionkey) || string.IsNullOrEmpty(cookieSessionUserName))
                {
                    //直接登录
                    filterContext.Result = SsoLoginResult(cookieSessionUserName);
                }
                else
                {
                    //验证
                    if (CheckLogin(cookieSessionkey, filterContext.HttpContext.Request.RawUrl) == false)
                    {
                        //会话丢失，跳转到登录页面
                        filterContext.Result = SsoLoginResult(cookieSessionUserName);
                    }
                    else
                    {
                        var claims = new List<Claim>();
                        claims.Add(new Claim(ClaimTypes.Name, "Brock"));
                        claims.Add(new Claim(ClaimTypes.Email, "brockallen@gmail.com"));
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, cookieSessionkey));
                        var id = new ClaimsIdentity(claims,
                                                    DefaultAuthenticationTypes.ApplicationCookie);

                        var ctx = filterContext.HttpContext.Request.GetOwinContext();
                        var authenticationManager = ctx.Authentication;
                        authenticationManager.SignIn(id);
                    }
                }
            }
        }

        public static bool CheckLogin(string sessionKey, string remark = "")
        {
            var httpClient = new HttpClient
            {
                BaseAddress = new Uri(ConfigurationManager.AppSettings["SSOPassport"])
            };

            var requestUri = string.Format("api/Passport?sessionKey={0}&remark={1}", sessionKey, remark);

            try
            {
                var resp = httpClient.GetAsync(requestUri).Result;

                resp.EnsureSuccessStatusCode();

                return resp.Content.ReadAsAsync<bool>().Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private static ActionResult SsoLoginResult(string username)
        {
            return new RedirectResult(string.Format("{0}/passport?appkey={1}&username={2}",
                    ConfigurationManager.AppSettings["SSOPassport"],
                    ConfigurationManager.AppSettings["SSOAppKey"],
                    username));
        }
    }
}
