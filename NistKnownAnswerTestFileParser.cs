using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Parses the AES NIST Known Answer Test (KAT) files.
    /// </summary>
    internal static class NistKnownAnswerTestFileParser
    {
        private static CipherMode GetCipherModeFromFileName(string path)
        {
            string fileMode = Path.GetFileName(path).Substring(0, 3);
            try
            {
                CipherMode result = (CipherMode) Enum.Parse(typeof (CipherMode), fileMode);
                return result;
            }
            catch (ArgumentException)
            {
                // Hacked way of doing a TryParse
                return 0;
            }
        }

        public static bool IsValidTestFileName(string path)
        {
            return GetCipherModeFromFileName(path) != 0;
        }

        public static IEnumerable<NistKnownAnswerTestVector> Parse(string path)
        {
            CipherMode cipherMode = GetCipherModeFromFileName(path);
            using (var reader = new StreamReader(path))
            {
                string firstLine = reader.ReadLine();

                NistKnownAnswerTestOperation operation;

                switch (firstLine)
                {
                    case "[ENCRYPT]":
                        operation = NistKnownAnswerTestOperation.Encrypt;
                        break;
                    case "[DECRYPT]":
                        operation = NistKnownAnswerTestOperation.Decrypt;
                        break;
                    default:
                        throw new InvalidDataException("Unknown operation");
                }

                string currentLine;

                while ((currentLine = reader.ReadLine()) != null)
                {
                    if (currentLine.Trim().Length == 0)
                    {
                        continue;
                    }

                    yield return ReadVector(operation, cipherMode, currentLine, reader);
                }
            }
        }

        private static NistKnownAnswerTestVector ReadVector(NistKnownAnswerTestOperation operation,
                                                            CipherMode cipherMode, string firstLine, StreamReader reader)
        {
            string[] countInfo = ParseNameValuePair(firstLine);

            if (!"COUNT".Equals(countInfo[0], StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Expected COUNT as first item");
            }

            int count = Int32.Parse(countInfo[1], CultureInfo.InvariantCulture);

            string name;
            byte[] bytes;
            int bitLength;
            ParseNamedBytes(reader.ReadLine(), out name, out bytes, out bitLength);
            if (!"KEY".Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Expected KEY");
            }

            byte[] key = bytes;

            ParseNamedBytes(reader.ReadLine(), out name, out bytes, out bitLength);

            byte[] iv = null;

            // IV is optional since ECB doesn't need it
            if ("IV".Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                iv = bytes;
                ParseNamedBytes(reader.ReadLine(), out name, out bytes, out bitLength);
            }

            byte[] plaintext;
            byte[] ciphertext;

            if (operation == NistKnownAnswerTestOperation.Encrypt)
            {
                if (!"PLAINTEXT".Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Expected PLAINTEXT");
                }

                plaintext = bytes;

                ParseNamedBytes(reader.ReadLine(), out name, out bytes, out bitLength);

                if (!"CIPHERTEXT".Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Expected CIPHERTEXT");
                }

                ciphertext = bytes;
            }
            else
            {
                if (!"CIPHERTEXT".Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Expected CIPHERTEXT");
                }

                ciphertext = bytes;

                ParseNamedBytes(reader.ReadLine(), out name, out bytes, out bitLength);

                if (!"PLAINTEXT".Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Expected PLAINTEXT");
                }

                plaintext = bytes;
            }

            return new NistKnownAnswerTestVector(operation, cipherMode, count, key, iv, bitLength, plaintext, ciphertext);
        }

        private static string[] ParseNameValuePair(string line)
        {
            return line.Split(new[] {' ', '='}, StringSplitOptions.RemoveEmptyEntries);
        }

        private static void ParseNamedBytes(string line, out string name, out byte[] bytes, out int bitLength)
        {
            string[] nameValue = ParseNameValuePair(line);
            name = nameValue[0];

            if (nameValue[1].Length == 1)
            {
                bitLength = 1;
                bytes = new[] {(byte) (Int32.Parse(nameValue[1])*0x80)};
                return;
            }

            bytes = ByteUtilities.GetBytes(nameValue[1]);
            bitLength = bytes.Length*Constants.BitsPerByte;
        }
    }

    internal enum NistKnownAnswerTestOperation
    {
        Encrypt,
        Decrypt
    }

    /// <summary>
    /// Represents a single NIST KAT test vector.
    /// </summary>
    internal class NistKnownAnswerTestVector
    {
        public NistKnownAnswerTestVector(NistKnownAnswerTestOperation operation, CipherMode cipherMode, int count,
                                         byte[] key, byte[] iv, int bitLength, byte[] plaintext, byte[] ciphertext)
        {
            Operation = operation;
            CipherMode = cipherMode;
            Count = count;
            Key = key;
            IV = iv;
            BitLength = bitLength;
            Plaintext = plaintext;
            Ciphertext = ciphertext;
        }

        public NistKnownAnswerTestOperation Operation { get; private set; }
        public CipherMode CipherMode { get; private set; }
        public int Count { get; private set; }
        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }
        public byte[] Plaintext { get; private set; }
        public byte[] Ciphertext { get; private set; }
        public int BitLength { get; private set; }
    }
}