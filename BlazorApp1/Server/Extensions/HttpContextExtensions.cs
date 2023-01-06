
using Microsoft.VisualBasic;

namespace BlazorApp1.Server.Extensions
{
    public static class HttpContextExtensions
    {
        //public static Alias GetAlias(this HttpContext context)
        //{
        //    if (context != null && context.Items.ContainsKey(Constants.HttpContextAliasKey))
        //    {
        //        return context.Items[Constants.HttpContextAliasKey] as Alias;
        //    }
        //    return null;
        //}

        public static Dictionary<string, string> GetSiteSettings(this HttpContext context)
        {
            if (context != null && context.Items.ContainsKey("SiteSettings"))
            {
                return context.Items["SiteSettings"] as Dictionary<string, string>;
            }
            return null;
        }
    }
}
