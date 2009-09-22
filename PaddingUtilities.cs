using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Functions that apply and verify a given <see cref="System.Security.Cryptography.PaddingMode"/>.
    /// </summary>
    internal static class PaddingUtilities
    {
        private static readonly RandomNumberGenerator _Random = RandomNumberGenerator.Create();

        public static int GetPaddingBytesNeeded(PaddingMode mode, int byteLength, int blockSizeInBytes)
        {
            if (mode == PaddingMode.None)
            {
                return 0;
            }

            return blockSizeInBytes - byteLength;
        }

        public static byte[] ApplyPadding(PaddingMode mode, byte[] bytes, int blockSizeInBytes)
        {
            int paddingBytesNeeded = GetPaddingBytesNeeded(mode, bytes.Length, blockSizeInBytes);
            if (paddingBytesNeeded == 0)
            {
                // sanity check
                return ByteUtilities.Clone(bytes);
            }

            byte[] output = new byte[blockSizeInBytes];
            Buffer.BlockCopy(bytes, 0, output, 0, bytes.Length);

            switch (mode)
            {
                case PaddingMode.ANSIX923:
                    ApplyAnsiX923Padding(output, paddingBytesNeeded);
                    break;
                case PaddingMode.ISO10126:
                    ApplyIso10126Padding(output, paddingBytesNeeded);
                    break;
                case PaddingMode.PKCS7:
                    ApplyPkcs7Padding(output, paddingBytesNeeded);
                    break;
                case PaddingMode.Zeros:
                    // nop
                    break;
                default:
                    throw new NotImplementedException("Padding mode not implemented");
            }

            return output;
        }

        public static byte[] RemovePadding(PaddingMode mode, byte[] bytes)
        {            
            switch (mode)
            {
                case PaddingMode.None:
                case PaddingMode.Zeros:
                    return ByteUtilities.Clone(bytes);
                case PaddingMode.ANSIX923:
                    return RemoveAnsiX923Padding(bytes);
                case PaddingMode.ISO10126:
                    return RemoveIso10126Padding(bytes);
                case PaddingMode.PKCS7:
                    return RemovePkcs7Padding(bytes);
                default:
                    throw new NotImplementedException("Padding mode not implemented");
            }
        }

        // (from MSDN)
        // The ANSIX923 padding string consists of a sequence of bytes filled with zeros before the length.
        // The following example shows how this mode works. Given a blocklength of 8, a data length of 9, the number of padding octets equal to 7, and the data equal to FF FF FF FF FF FF FF FF FF:
        // Data: FF FF FF FF FF FF FF FF FF
        // X923 padding: FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 07

        private static void ApplyAnsiX923Padding(byte[] output, int paddingBytesNeeded)
        {        
            output[output.Length - 1] = (byte) paddingBytesNeeded;
            // The buffer is initialized to all 0's, so no need to do that here            
        }

        private static byte[] RemoveAnsiX923Padding(byte[] bytes)
        {
            int paddingByteCount = GetPaddingByteCount(bytes);
            return RemovePadding(bytes, paddingByteCount, 0x00);        
        }
                
        // ISO 10126 Padding:
        // (from MSDN)
        // The ISO10126 padding string consists of random data before the length.
        // The following example shows how this mode works. Given a blocklength of 8, a data length of 9, the number of padding octets equal to 7, and the data equal to FF FF FF FF FF FF FF FF FF:
        // Data: FF FF FF FF FF FF FF FF FF
        // ISO10126 padding: FF FF FF FF FF FF FF FF FF 7D 2A 75 EF F8 EF 07
        private static void ApplyIso10126Padding(byte[] output, int paddingBytesNeeded)
        {
            byte[] randomBytes = new byte[paddingBytesNeeded - 1];
            _Random.GetBytes(randomBytes);

            output[output.Length - 1] = (byte) paddingBytesNeeded;
            Buffer.BlockCopy(randomBytes, 0, output, output.Length - paddingBytesNeeded, randomBytes.Length);
        }

        private static byte[] RemoveIso10126Padding(byte[] paddedBytes)
        {
            int paddingByteCount = GetPaddingByteCount(paddedBytes);
            // Can't verify randomness :)
            return ByteUtilities.Truncate(paddedBytes, paddedBytes.Length - paddingByteCount);
        }

        // PKCS #7 Padding:
        // (from MSDN)
        // The PKCS #7 padding string consists of a sequence of bytes, each of which is equal to the total number of padding bytes added. 
        // The following example shows how these modes work. Given a blocklength of 8, a data length of 9, the number of padding octets equal to 7, and the data equal to FF FF FF FF FF FF FF FF FF:
        // Data: FF FF FF FF FF FF FF FF FF
        // PKCS7 padding: FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07

        private static void ApplyPkcs7Padding(byte[] output, int paddingBytesNeeded)
        {
            for (int i = output.Length - paddingBytesNeeded; i < output.Length; i++)
            {
                output[i] = (byte) paddingBytesNeeded;
            }
        }

        private static byte[] RemovePkcs7Padding(byte[] paddedBytes)
        {
            int paddingByteCount = GetPaddingByteCount(paddedBytes);
            return RemovePadding(paddedBytes, paddingByteCount, (byte)paddingByteCount);
        }

        private static CryptographicException InvalidPadding
        {
            get
            {
                return new CryptographicException("Invalid Padding");
            }
        }

        private static int GetPaddingByteCount(byte[] buffer)
        {
            int paddingBytes = buffer[buffer.Length - 1];

            if (paddingBytes > buffer.Length)
            {
                throw InvalidPadding;
            }

            return paddingBytes;
        }

        private static byte[] RemovePadding(byte[] buffer, int paddingByteCount, byte expectedPaddingByte)
        {
            for (int i = buffer.Length - paddingByteCount; i < (buffer.Length - 1); i++)
            {
                if (buffer[i] != expectedPaddingByte)
                {
                    throw InvalidPadding;
                }
            }

            return ByteUtilities.Truncate(buffer, buffer.Length - paddingByteCount);
        }
    }
}