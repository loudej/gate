using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using Owin;

namespace Gate.Middleware
{
    public static class BasicAuth
    {
        public class Options
        {
            public string Realm { get; set; }
            public Func<string, string, bool> Authenticator { get; set; }
            public bool DenyAnonymous { get; set; }
            public Func<IDictionary<string, object>, bool> Predicate { get; set; }

            public Options WithRealm(string realm)
            {
                Realm = realm;
                return this;
            }
            public Options WithAuthenticator(Func<string, string, bool> authenticator)
            {
                Authenticator = authenticator;
                return this;
            }
            public Options WithDenyAnonymous(bool denyAnonymous = true)
            {
                DenyAnonymous = denyAnonymous;
                return this;
            }
            public Options WithPredicate(Func<IDictionary<string, object>, bool> predicate)
            {
                Predicate = predicate;
                return this;
            }
        }

        public static IAppBuilder UseBasicAuth(this IAppBuilder builder, string realm, Func<string, string, bool> authenticator, Action<Options> options)
        {
            var opt = new Options().WithRealm(realm).WithAuthenticator(authenticator);
            options(opt);
            return builder.Use(Middleware, opt);
        }

        public static IAppBuilder UseBasicAuth(this IAppBuilder builder, string realm, Func<string, string, bool> authenticator)
        {
            return builder.Use(Middleware, new Options().WithRealm(realm).WithAuthenticator(authenticator));
        }

        public static IAppBuilder UseBasicAuth(this IAppBuilder builder, Options options)
        {
            return builder.Use(Middleware, options);
        }

        public static IAppBuilder UseBasicAuth(this IAppBuilder builder, Action<Options> options)
        {
            var opt = new Options();
            options(opt);
            return builder.Use(Middleware, opt);
        }


        public static AppDelegate Middleware(AppDelegate app, Options options)
        {
            var shouldExecute = ShouldExecute(options.Predicate ?? (_ => true));

            var execute = Execute(app, options);

            return (env, result, fault) => (shouldExecute(env) ? execute : app).Invoke(env, result, fault);
        }

        private static Func<IDictionary<string, object>, bool> ShouldExecute(Func<IDictionary<string, object>, bool> predicate)
        {
            return env =>
            {
                var isAuthenticated = false;

                object value;
                if (env.TryGetValue("System.Security.Principal.IIdentity", out value))
                {
                    var identity = value as IIdentity;
                    if (identity != null && identity.IsAuthenticated)
                    {
                        isAuthenticated = true;
                    }
                }

                return !isAuthenticated && predicate(env);
            };
        }

        private static AppDelegate Execute(AppDelegate app, Options options)
        {
            var challenge = string.Format("Basic realm=\"{0}\"", options.Realm);

            if (options.DenyAnonymous)
            {
                app = DenyAnonymous.Middleware(app);
            }

            return (env, result, fault) =>
            {
                Authenticate(env, options.Authenticator);

                app.Invoke(env,
                    (status, headers, body) =>
                    {
                        if (status.StartsWith("401"))
                        {
                            headers.AddHeader("WWW-Authenticate", challenge);
                        }
                        result(status, headers, body);
                    },
                    fault);
            };
        }

        private static void Authenticate(IDictionary<string, object> env, Func<string, string, bool> authenticator)
        {
            const string authorizationKey = "Authorization";
            var environment = new Environment(env);

            if (!environment.Headers.ContainsKey(authorizationKey))
            {
                return;
            }

            var authorizationHeader = environment.Headers[authorizationKey].ToArray().First();
            var headerValues = authorizationHeader.Split(new[] { ' ' }, 2);
            var scheme = headerValues[0];
            if (!string.Equals(scheme, "Basic", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var param = headerValues[1];

            var credentials = Encoding.ASCII.GetString(Convert.FromBase64String(param)).Split(new[] { ':' }, 2);
            var username = credentials[0];
            var password = credentials[1];
            if (!authenticator(username, password))
            {
                return;
            }

            env["System.Security.Principal.IIdentity"] = new GenericIdentity(username, "Basic");
        }
    }
}