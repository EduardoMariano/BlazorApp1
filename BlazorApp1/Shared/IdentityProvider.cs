using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlazorApp1.Shared
{
    public class IdentityProvider
    {
        public string? AuthenticationScheme { get; set; }
        public string? DisplayName { get; set; }
        public string? MetadataAddress { get; set; }
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public string? CallbackPath { get; set; }
        public string? SignedOutCallbackPath { get; set; }
    }
}
