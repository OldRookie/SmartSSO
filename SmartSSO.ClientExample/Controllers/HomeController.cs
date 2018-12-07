using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using SmartSSO.Mvc;
using SmartSSO.Mvc.Filters;

namespace SmartSSO.ClientExample.Controllers
{
    [BaseAuthorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            //var claims = new List<Claim>();
            //claims.Add(new Claim(ClaimTypes.Name, "Brock"));
            //claims.Add(new Claim(ClaimTypes.Email, "brockallen@gmail.com"));
            //var id = new ClaimsIdentity(claims,
            //                            DefaultAuthenticationTypes.ApplicationCookie);

            //var ctx = Request.GetOwinContext();
            //var authenticationManager = ctx.Authentication;
            //authenticationManager.SignIn(id);
            return View();
        }

        public ActionResult About()
        {
            var ctx = Request.GetOwinContext();
            ClaimsPrincipal user = ctx.Authentication.User;

            ViewBag.Message = "Your application description page.";

            return View();
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        public ActionResult LogOff()
        {
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            ClaimsPrincipal user = ctx.Authentication.User;
            var claim = user.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            
            LogOff(claim.Value);
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        public static bool LogOff(string sessionKey, string remark = "")
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

                //return resp.Content.re<bool>().Result;
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}