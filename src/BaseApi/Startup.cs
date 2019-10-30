using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using BaseApi.Configuration;
using BaseApi.Identity;
using BaseApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;


namespace BaseApi
{
    public class Startup

    {
        private IConfiguration _configuration;
        private readonly ILogger<Startup> _logger;
        public Startup(ILogger<Startup> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            _logger.LogInformation("Registrando classes de Configuração...");

            #region [ Configurations ]
            services.Configure<PasswordConfiguration>(options => _configuration.GetSection(nameof(PasswordConfiguration)).Bind(options));
            services.Configure<TokenConfiguration>(options => _configuration.GetSection(nameof(TokenConfiguration)).Bind(options));
            #endregion

            _logger.LogInformation("Registrando Autenticação e Autorização...");

            #region [ Authentication ]
            services.AddIdentity<User, RoleStore>(options =>
            {
                var passwordConfiguration = new PasswordConfiguration();
                _configuration.GetSection(nameof(PasswordConfiguration)).Bind(passwordConfiguration);

                options.Lockout.AllowedForNewUsers = passwordConfiguration.UserLockoutEnabled;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(passwordConfiguration.LockoutTimeSpan);
                options.Lockout.MaxFailedAccessAttempts = passwordConfiguration.LockoutMaxFailedAccess;

                options.SignIn.RequireConfirmedEmail = passwordConfiguration.RequireConfirmedEmail;
                options.SignIn.RequireConfirmedPhoneNumber = false;

                options.Password.RequireDigit = passwordConfiguration.RequireDigit;
                options.Password.RequiredLength = passwordConfiguration.RequiredLength;
                options.Password.RequireNonAlphanumeric = passwordConfiguration.RequireNonAlphanumeric;
                options.Password.RequireUppercase = passwordConfiguration.RequireUppercase;
                options.Password.RequireLowercase = passwordConfiguration.RequireLowercase;
            }).AddDefaultTokenProviders().AddErrorDescriber<AuthorizationIdentityErrorDescriber>();


            services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOptions =>
            {
                var tokenConfiguration = new TokenConfiguration();
                _configuration.GetSection(nameof(TokenConfiguration)).Bind(tokenConfiguration);

                var paramsValidation = bearerOptions.TokenValidationParameters;
                paramsValidation.ValidateIssuer = true;
                paramsValidation.ValidateAudience = true;
                // Valida a assinatura de um token recebido
                paramsValidation.ValidateIssuerSigningKey = true;
                // Verifica se um token recebido ainda é válido
                paramsValidation.ValidateLifetime = true;

                paramsValidation.IssuerSigningKey = tokenConfiguration.AccessKey;
                paramsValidation.ValidAudience = tokenConfiguration.Audience;
                paramsValidation.ValidIssuer = tokenConfiguration.Issuer;

                // Tempo de tolerância para a expiração de um token (utilizado
                // caso haja problemas de sincronismo de horário entre diferentes
                // computadores envolvidos no processo de comunicação)
                paramsValidation.ClockSkew = TimeSpan.Zero;

                bearerOptions.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        var accessToken = context.Request.Query["token"];

                        // If the request is for our hub...
                        var path = context.HttpContext.Request.Path;
                        if (!string.IsNullOrEmpty(accessToken) &&
                            (path.StartsWithSegments("/hubs/notifications")))
                        {
                            // Read the token out of the query string
                            context.Token = accessToken;
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            services.AddAuthorization(auth =>
            {
                auth.AddPolicy(JwtBearerDefaults.AuthenticationScheme, new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build());
            });
            #endregion

            _logger.LogInformation("Registrando CORS ...");

            #region [ Cors ]

            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                {
                    //builder.WithOrigins(appConfiguration.Origins).AllowAnyMethod().AllowAnyHeader().AllowCredentials();
                    builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader().AllowCredentials();
                });
            });
            #endregion

            _logger.LogInformation("Registrando Swagger...");

            #region [ SWAGGER ]
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Base Api",
                    Version = "v1",
                    Description = "Documentação da Base Api."
                });

                c.IncludeXmlComments(GetXmlCommentsPath());

                //c.DescribeAllEnumsAsStrings();

                

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header,
                            
                        },
                        new List<string>()
                    }
                });


            });

            #endregion

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private string GetXmlCommentsPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, String.Format("{0}.xml", this.AppName()));
        }

        private string AppName()
        {
            return Assembly.GetCallingAssembly().GetName().Name;
        }
    }


}
