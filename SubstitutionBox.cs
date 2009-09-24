namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Provides a non-linear substitution for bytes.
    /// </summary>
    internal static class SubstitutionBox
    {
        private static readonly byte[] _InvSBox;
        private static readonly byte[] _SBox;

        static SubstitutionBox()
        {
            _SBox = CalculateSBox(out _InvSBox);
        }

        private static byte[] CalculateSBox(out byte[] invSBox)
        {
            byte[] result = new byte[256];
            invSBox = new byte[256];

            // We use an int since a byte would cause this to loop forever due to overflow
            for (int i = 0; i < 256; i++)
            {
                byte currentByte = (byte) i;
                result[i] = FiniteFieldMath.F(FiniteFieldMath.G(currentByte));
                invSBox[result[i]] = currentByte;
            }

            return result;
        }

        public static byte Value(int offset)
        {
            return _SBox[offset];
        }

        public static byte Inverse(int offset)
        {
            return _InvSBox[offset];
        }        
    }
}