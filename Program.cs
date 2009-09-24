using System;
using System.Security.Cryptography;
using System.Text;

namespace Moserware.AesIllustrated
{
    internal class Program
    {
        /// <summary>
        /// Entry point to demonstration of the Advanced Encryption Standard (aka "Rijndael")
        /// </summary>        
        private static void Main()
        {
            // Hopefully this class makes it easier for you to understand how AES/Rijndael work.

            // The idea is that you can step through each of these functions in the debugger 
            // and take a look at the console window while you do it. 

            // Good luck! 
            ShowExamplesOfRijndaelMath();
            ShowSBox();
            ShowWorkedExample();
            ShowRijndaelBookTestVectors();
            ShowWikipediaTestVectors();
            ShowNistTestVectorComparison();    
            ShowCapiComparison();
        }
                
        private static void ShowExamplesOfRijndaelMath()
        {
            WriteHeader("Rijndael Math");
            string m = "x^8 + " + ByteUtilities.ToPolynomial(0x1B);
            Console.WriteLine("Rijndael involves math in a finite field modulo m(x) = {0} where bytes are treated as polynomials", m);
            Console.WriteLine();
            Console.WriteLine("Some examples:");

            const byte left = 0x1B;
            const byte right = 0xAA;

            Console.WriteLine("({0}) * ({1}) = {2:X2} * {3:X2}", left.ToPolynomial(), right.ToPolynomial(), left, right);

            byte logLeft = FiniteFieldMath.Log(left);
            byte logRight = FiniteFieldMath.Log(right);
            byte logAddition = (byte) (logLeft + logRight);
            Console.WriteLine("Log({0:X2}) + Log({1:X2}) = {2:X2} ^ {3:X2} = {4:X2}", left, right, logLeft, logRight, logAddition);
            Console.WriteLine("AntiLog({0:X2}) = Log^-1 ({0:X2}) = {1:X2}", logAddition, FiniteFieldMath.AntiLog(logAddition));
            Console.WriteLine("So {0:X2} * {1:X2} = {2:X2}", left, right, FiniteFieldMath.Multiply(left, right));
            Console.WriteLine();
            


            byte accumulator = 0x01;

            for (int i = 0; i < 0x10; i++)
            {
                const byte multiplier = 0x03;
                byte newResult = FiniteFieldMath.Multiply(accumulator, multiplier);
                Console.WriteLine(
                    "({0}) * ({1}) = {2} => {3:X2} * {4:X2} = {5:X2}",
                    multiplier.ToPolynomial(),
                    accumulator.ToPolynomial(),
                    newResult.ToPolynomial(),
                    multiplier,
                    accumulator,
                    newResult);
                accumulator = newResult;
            }

            Random weakRng = new Random();

            Console.WriteLine();
            Console.WriteLine("Rijndael's substitution box uses the \"g\" function that gives inverses in the field: g(a) = a^-1 mod m");
            Console.WriteLine();
            Console.WriteLine("Examples of a * g(a):");
            for(int i = 0; i < 5; i++)
            {
                byte currentByte = (byte)weakRng.Next(2, 256);
                byte inverseByte = FiniteFieldMath.G(currentByte);
                byte resultByte = FiniteFieldMath.Multiply(currentByte, inverseByte);

                Console.WriteLine(
                    "({0}) * ({1}) = {2} => {3:X2} * {4:X2} = {5:X2}",
                    currentByte.ToPolynomial(),
                    inverseByte.ToPolynomial(),
                    resultByte.ToPolynomial(),
                    currentByte,
                    inverseByte,
                    resultByte);
            }

            Console.WriteLine();
            Console.WriteLine("The actual s-box values is f(g(a)) where \"f\" is an affine transform");
            Console.WriteLine();
            Console.WriteLine("Some examples:");
            for(int i = 0; i < 5; i++)
            {
                byte currentByte = (byte)weakRng.Next(2, 256);
                byte resultByte = FiniteFieldMath.F(FiniteFieldMath.G(currentByte));

                Console.WriteLine("f(g({0:X2})) = {1:X2}", currentByte, resultByte);
            }
        }

        private static void ShowSBox()
        {
            WriteHeader("S-Boxes");
            WriteBox("Rijndael S-Box (SRD[x]):", SubstitutionBox.Value);        
            WriteBox("Rijndael Inverse S-Box (SRD^1[x]):", SubstitutionBox.Inverse);

            const byte val = 0x42;
            byte srdVal = SubstitutionBox.Value(val);
            byte srdInvVal = SubstitutionBox.Inverse(srdVal);
            Console.WriteLine("Notice how SRD[{0:X2}] = {1:X2} and SRD^-1[{1:X2}] = {2:X2}", val, srdVal, srdInvVal);
        }

        private static void WriteBox(string title, Func<int, byte> boxRetriever)
        {
            Console.WriteLine(title);
            Console.WriteLine();
            Console.Write("     ");
            for (int col = 0; col < 16; col++)
            {
                Console.Write("{0:X2} ", col);
            }
            Console.WriteLine();
            Console.Write("   +" + new String('-', 48));
            Console.WriteLine();

            for (int row = 0; row < 16; row++)
            {
                Console.Write("{0:X2} | ", row * 16);
                for (int col = 0; col < 16; col++)
                {
                    Console.Write(boxRetriever((row * 16) + col).ToString("X2") + " ");
                }
                Console.WriteLine();
            }

            Console.WriteLine();
        }

        private static void ShowWorkedExample()
        {
            WriteHeader("Worked Example");
            using (Debugging.CreateDebuggingScope())
            {
                // The debugging scope will show debug information for key setup and each round.
                const string plaintext = "ATTACK AT DAWN!";
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                byte[] paddedBytes = PaddingUtilities.ApplyPadding(PaddingMode.PKCS7, plaintextBytes,
                                                                   Constants.AesBlockSize / Constants.BitsPerByte);

                const string key = "SOME 128 BIT KEY";
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);

                Debugging.Trace("Encrypting \"{0}\" with the key \"{1}\"", plaintext, key);
                var encryptedBytes = Aes.Encrypt(paddedBytes, keyBytes);
            }
        }

        private static void ShowRijndaelBookTestVectors()
        {
            WriteHeader("Rijndael Book Test");
            Console.WriteLine("Here are the test vectors from Appendix D of \"The Design of Rijndael\" book.");
            Console.WriteLine("(Note how there are more variants than AES allows)");
            Console.WriteLine();
            for (int keyLength = 128; keyLength <= 256; keyLength += 32)
            {
                for (int blockLength = 128; blockLength <= 256; blockLength += 32)
                {
                    Console.WriteLine("block length {0}  key length {1}", blockLength, keyLength);
                    byte[] blockBytes = new byte[blockLength / Constants.BitsPerByte];
                    byte[] keyBytes = new byte[keyLength / Constants.BitsPerByte];

                    var encrypted = Rijndael.Encrypt(blockBytes, keyBytes);
                    ByteUtilities.WriteBytes(encrypted);
                    var decrypted = Rijndael.Decrypt(encrypted, keyBytes);

                    for (int i = 0; i < decrypted.Length; i++)
                    {
                        if(decrypted[i] != 0)
                        {
                            throw new CryptographicException("The decrypted Rijndael book values were not all zero.");
                        }
                    }

                    var encryptedAgain = Rijndael.Encrypt(encrypted, keyBytes);
                    ByteUtilities.WriteBytes(encryptedAgain);

                    var decryptedAgain = Rijndael.Decrypt(encryptedAgain, keyBytes);
                    ByteUtilities.AssertBytesEqual(decryptedAgain, encrypted);
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
        }

        private static void ShowWikipediaTestVectors()
        {
            WriteHeader("Wikipedia Test Vectors Comparison");
            // Test vectors came from http://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Test_vectors on 7 Sep 2009
            byte[] input = ByteUtilities.GetBytes("4EC137A426DABF8AA0BEB8BC0C2B89D6");
            byte[] aes128Key = ByteUtilities.GetBytes("95A8EE8E89979B9EFDCBC6EB9797528D");
            byte[] cipheredOutput128 = Aes.Encrypt(input, aes128Key);
            byte[] decipheredOutput128 = Aes.Decrypt(input, aes128Key);

            byte[] wikipediaExpectedCipheredOutput128 = ByteUtilities.GetBytes("D9B65D1232BA0199CDBD487B2A1FD646");
            byte[] wikipediaExpectedDecipheredOutput128 = ByteUtilities.GetBytes("9570C34363565B393503A001C0E23B65");
            ByteUtilities.AssertBytesEqual(wikipediaExpectedCipheredOutput128, cipheredOutput128);
            ByteUtilities.AssertBytesEqual(wikipediaExpectedDecipheredOutput128, decipheredOutput128);

            byte[] aes192Key = ByteUtilities.GetBytes("95A8EE8E89979B9EFDCBC6EB9797528D432DC26061553818");
            byte[] cipheredOutput192 = Aes.Encrypt(input, aes192Key);
            byte[] decipheredOutput192 = Aes.Decrypt(input, aes192Key);

            byte[] wikipediaExpectedCipheredOutput192 = ByteUtilities.GetBytes("B18BB3E7E10732BE1358443A504DBB49");
            byte[] wikipediaExpectedDecipheredOutput192 = ByteUtilities.GetBytes("29DFD75B85CEE4DE6E26A808CDC2C9C3");

            ByteUtilities.AssertBytesEqual(wikipediaExpectedCipheredOutput192, cipheredOutput192);
            ByteUtilities.AssertBytesEqual(wikipediaExpectedDecipheredOutput192, decipheredOutput192);

            byte[] aes256Key = ByteUtilities.GetBytes("95A8EE8E89979B9EFDCBC6EB9797528D432DC26061553818EA635EC5D5A7727E");
            byte[] cipheredOutput256 = Aes.Encrypt(input, aes256Key);
            byte[] decipheredOutput256 = Aes.Decrypt(input, aes256Key);

            byte[] wikipediaExpectedCipheredOutput256 = ByteUtilities.GetBytes("2F9CFDDBFFCDE6B9F37EF8E40D512CF4");
            byte[] wikipediaExpectedDecipheredOutput256 = ByteUtilities.GetBytes("110A3545CE49B84BBB7B35236108FA6E");

            ByteUtilities.AssertBytesEqual(wikipediaExpectedCipheredOutput256, cipheredOutput256);
            ByteUtilities.AssertBytesEqual(wikipediaExpectedDecipheredOutput256, decipheredOutput256);
            Console.WriteLine("6 vectors passed");
        }        

        private static void ShowNistTestVectorComparison()
        {
            WriteHeader("NIST Test Vectors Comparison");
            NistKnownAnswerTestVectors.VerifyAllTestVectors();
        }

        private static void ShowCapiComparison()
        {
            WriteHeader("CAPI Comparison Test");
            Console.WriteLine("Checking output with the Windows Cryptographic API (CAPI) AES implementation");
            int totalTests = RandomizedCapiTests.PerformRandomizedTests();
            Console.WriteLine("Passed {0} randomized tests!", totalTests);
        }
        
        private static void WriteHeader(string headerName)
        {
            int dashesNeededPerSide = (Console.BufferWidth - headerName.Length - (" ".Length*2))/2;
            string dashes = new string('-', dashesNeededPerSide);

            Console.WriteLine();
            Console.WriteLine("{0} {1} {0}", dashes, headerName);
        }
    
    }
}