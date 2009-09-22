using System.IO;

namespace Moserware.AesIllustrated
{
    internal static class ProjectPaths
    {
        public static string NistKnownAnswerTestVectorsDirectory
        {
            get { return Path.Combine(SourceCodeRootDirectory, "NIST Known Answer Test Vectors"); }
        }

        public static string SourceCodeRootDirectory
        {
            get
            {
                return
                    (new FileInfo(Path.Combine(Path.GetDirectoryName(typeof (ProjectPaths).Assembly.Location), @"..\..")))
                        .FullName;
            }
        }
    }
}