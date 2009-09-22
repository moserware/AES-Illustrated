using System;

namespace Moserware.AesIllustrated
{
    internal static class Debugging
    {
        public static bool IsEnabled { get; set; }

        private class DebuggingScope : IDisposable
        {
            public DebuggingScope()
            {
                IsEnabled = true;
            }

            public void Dispose()
            {
                IsEnabled = false;
            }
        }

        public static IDisposable CreateDebuggingScope()
        {
            return new DebuggingScope();
        }

        public static void Trace(string format, params object[] args)
        {
            if(!IsEnabled)
            {
                return;
            }
            Console.WriteLine(format, args);
        }
    }
}
