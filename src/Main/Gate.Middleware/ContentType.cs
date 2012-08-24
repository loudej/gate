﻿using Gate.Middleware;
using Owin;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using Gate.Middleware.Utils;

namespace Owin
{
    public static class ContentTypeExtensions
    {
        public static IAppBuilder UseContentType(this IAppBuilder builder)
        {
            return builder.UseType<ContentType>();
        }

        public static IAppBuilder UseContentType(this IAppBuilder builder, string contentType)
        {
            return builder.UseType<ContentType>(contentType);
        }
    }
}

namespace Gate.Middleware
{
    using AppFunc = Func<IDictionary<string, object>, Task>;

    /// <summary>
    /// Sets content-type for the response if none is present.
    /// </summary>
    public class ContentType
    {
        private readonly AppFunc nextApp;
        private readonly string contentType;
        private const string DefaultContentType = "text/html";

        public ContentType(AppFunc nextApp)
        {
            this.nextApp = nextApp;
            this.contentType = DefaultContentType;
        }

        public ContentType(AppFunc nextApp, string contentType)
        {
            this.nextApp = nextApp;
            this.contentType = contentType;
        }

        public Task Invoke(IDictionary<string, object> env)
        {
            Stream orriginalStream = env.Get<Stream>(OwinConstants.ResponseBody);
            TriggerStream triggerStream = new TriggerStream(orriginalStream);
            env[OwinConstants.ResponseBody] = triggerStream;

            triggerStream.OnFirstWrite = () =>
            {
                var responseHeaders = env.Get<IDictionary<string, string[]>>(OwinConstants.ResponseHeaders);
                if (!responseHeaders.HasHeader("Content-Type"))
                {
                    responseHeaders.SetHeader("Content-Type", contentType);
                }
            };

            return nextApp(env).Then(() =>
            {
                // Make sure this gets run even if there were no writes.
                triggerStream.OnFirstWrite();
            });
        }
    }
}
