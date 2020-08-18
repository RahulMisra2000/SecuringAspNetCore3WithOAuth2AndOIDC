using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;
using ImageGallery.Client.HttpHandlers;

namespace ImageGallery.Client
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();  /* So that the middleware does NOT change the names of the claim keys ---- */
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                 .AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);

            services.AddAuthorization(authorizationOptions =>
                {
                   authorizationOptions.AddPolicy(
                       "CanOrderFrame",
                       policyBuilder =>
                       {
                           policyBuilder.RequireAuthenticatedUser();
                           policyBuilder.RequireClaim("country", "be");
                           policyBuilder.RequireClaim("subscriptionlevel", "PayingUser");
                       });
                });

            services.AddHttpContextAccessor();

            services.AddTransient<BearerTokenHandler>();

            /* create an HttpClient used for accessing the API ------------------------- */
            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44366/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            })
            .AddHttpMessageHandler<BearerTokenHandler>();   /* Think of this like an handler that stuffs the AT in the http request going out to the APIs --- */
            
            /* create an HttpClient used for accessing the IDP -------------------------- */
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44318/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });


            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                /* If the cookie is invalid/corrupted/etc then which page to show to the user ---- */
                options.AccessDeniedPath = "/Authorization/AccessDenied";
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                /*** Configuring the Main middleware ---------------------------------------------------  */
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = "https://localhost:44318/";    /* The IdentityServer4 */
                options.ClientId = "imagegalleryclient";
                options.ClientSecret = "secret";
                options.ResponseType = "code";  /* Determines which flow will be used */ 
                
                /* The following scopes will be requested by this client application --------------------- */
                options.Scope.Add("address");
                options.Scope.Add("roles");
                options.Scope.Add("imagegalleryapi");
                options.Scope.Add("subscriptionlevel");
                options.Scope.Add("country");
                options.Scope.Add("offline_access");
                
                /* Don't copy these claims from the IT to ClaimsIdentity and therefore to User.Claims --------------------------- */
                /* Basically not interested in these claims that are in the IT. Since they end up in the cookie, we want to have a light cookie ---------------- */
                options.ClaimActions.DeleteClaim("sid");
                options.ClaimActions.DeleteClaim("idp");
                options.ClaimActions.DeleteClaim("s_hash");
                options.ClaimActions.DeleteClaim("auth_time");
                
                /* All custom scopes have to be specified here so that they are copied from the token to the ClaimsIdentity and then to User.Claims ------ */
                options.ClaimActions.MapUniqueJsonKey("role", "role");
                options.ClaimActions.MapUniqueJsonKey("subscriptionlevel", "subscriptionlevel");
                options.ClaimActions.MapUniqueJsonKey("country", "country");
                
                /* I think this allows it to be accessible via httpcontext.getTokenAsync()  */
                options.SaveTokens = true;
                
                /* So that this middleware will call the UserInfo Endpoint automatically and get the claims listed in the AT. We can of course 
                   make the call to this endpoint on demand as well ----*/
                options.GetClaimsFromUserInfoEndpoint = true;
                
                /* This is telling the middleware which claim key is for name and role, so later we can use the IsInRole(), etc  */
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.GivenName,
                    RoleClaimType = JwtClaimTypes.Role
                };
            });


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
 
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Shared/Error");
                // The default HSTS value is 30 days. You may want to change this for
                // production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Gallery}/{action=Index}/{id?}");
            });
        }
    }
}
