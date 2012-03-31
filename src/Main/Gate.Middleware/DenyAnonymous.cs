using System;
using System.Linq;
using System.Security.Principal;
using Owin;

namespace Gate.Middleware
{
    public static class DenyAnonymous
    {
        public static IAppBuilder UseDenyAnonymous(this IAppBuilder builder)
        {
            return builder.Use(Middleware);
        }

        public static IAppBuilder UseDenyAnonymous(this IAppBuilder builder, params string[] denyPaths)
        {
            return builder.Use(Middleware, denyPaths);
        }

        public static IAppBuilder UseDenyAnonymous(this IAppBuilder builder, StringComparison comparison, params string[] denyPaths)
        {
            return builder.Use(Middleware, comparison, denyPaths);
        }

        public static IAppBuilder UseDenyAnonymous(this IAppBuilder builder, Func<string, bool> denyTest)
        {
            return builder.Use(Middleware, denyTest);
        }

        public static AppDelegate Middleware(AppDelegate app)
        {
            return Middleware(app, path => true);
        }

        public static AppDelegate Middleware(AppDelegate app, params string[] denyPaths)
        {
            return Middleware(app, path => denyPaths.Any(denyPath => path.StartsWith(denyPath, StringComparison.OrdinalIgnoreCase)));
        }

        public static AppDelegate Middleware(AppDelegate app, StringComparison comparison, params string[] denyPaths)
        {
            return Middleware(app, path => denyPaths.Any(denyPath => path.StartsWith(denyPath, comparison)));
        }

        public static AppDelegate Middleware(AppDelegate app, Func<string, bool> denyTest)
        {
            return (env, result, fault) =>
            {
                var isAuthenticated = false;

                object value;
                if (env.TryGetValue("System.Security.Principal.IIdentity", out value))
                {
                    var identity = value as IIdentity;
                    if (identity != null && identity.IsAuthenticated)
                    {
                        isAuthenticated = identity.IsAuthenticated;
                    }
                }

                if (isAuthenticated || !denyTest((string)env["owin.RequestPath"]))
                {
                    app(env, result, fault);
                }
                else
                {
                    result.Invoke("401 Unauthorized", Headers.New(), (write, flush, end, cancel) => end(null));
                }
            };
        }

    }
}
