using System;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Contains the round keys for each round of Rijndael.
    /// </summary>
    internal class KeySchedule
    {
        private readonly int _PlaintextBlockSizeInBytes;
        private byte[] _Key;
        private ByteMatrix[] _RoundKeys;

        public KeySchedule(byte[] key, int plaintextBlockSizeInBytes)
        {
            _PlaintextBlockSizeInBytes = plaintextBlockSizeInBytes;
            Key = key;
        }

        /// <summary>
        /// The key that is used to generate the round keys.
        /// </summary>
        public byte[] Key
        {
            get { return _Key; }
            set { Rekey(value, _PlaintextBlockSizeInBytes); }
        }

        /// <summary>
        /// Gets the round key for the specified <paramref name="round"/>.
        /// </summary>
        /// <param name="round">The round to obtain the key for.</param>
        /// <returns>The round key for <paramref name="round"/>.</returns>
        public ByteMatrix GetRoundKey(int round)
        {
            return _RoundKeys[round];
        }

        /// <summary>
        /// Updates the key schedule with a new key and plaintext block size count.
        /// </summary>
        /// <param name="key">The key to derive round keys from.</param>
        /// <param name="plaintextBlockSizeInBytes">The intended plaintext block size.</param>
        private void Rekey(byte[] key, int plaintextBlockSizeInBytes)
        {
            _Key = key;
            
            int keyColumns = key.Length/Constants.StateRows;

            if (keyColumns < Constants.MinKeySizeColumns)
            {
                throw new ArgumentException("Key must be at least 128 bits", "key");
            }

            if ((key.Length%Constants.StateRows) != 0)
            {
                throw new ArgumentException("Key must be a multiple of 32 bits", "key");
            }

            ByteMatrix keyMatrix = new ByteMatrix(Constants.StateRows, key);

            int plaintextBlockSizeColumns = plaintextBlockSizeInBytes/Constants.StateRows;
            int numberOfRounds = Constants.GetRounds(keyMatrix.Columns, plaintextBlockSizeColumns);
            
            // There are Nr rounds, so Nb * (Nr + 1) round keys where Nr is the number of rounds (plus the initial round)
            // and Nb is the size of the block in columns.
            ByteMatrix allRoundKeys = new ByteMatrix(Constants.StateRows, plaintextBlockSizeColumns*(numberOfRounds + 1));

            // The initial round key (#0) is the key itself
            for (int col = 0; col < keyMatrix.Columns; col++)
            {
                for (int row = 0; row < Constants.StateRows; row++)
                {
                    allRoundKeys[row, col] = keyMatrix[row, col];
                }
            }

            ByteMatrix[] roundKeys = new ByteMatrix[numberOfRounds + 1];

            // 30 round constants are enough for a 256 bit block and a 256 bit key
            byte[] roundConstants = Constants.GetRoundConstants(30); 

            // The basic idea for the round keys is that you start with the initial round key
            // and then when you go to generate the next round key, you take the last column
            // of the previous round key and move it up by one byte (the previous top byte goes
            // to the bottom). Then you put each of the bytes of that column through the S-box.
            // Then you XOR the new top byte with the round key. Finally, you xor the whole column
            // with the column Nb columns earlier. 
            
            // The other columns are made by xor-ing the previous column with the column Nb columns
            // earlier. 

            // Say you have a key like this

            // | S |   |   |   |            
            // | O | 1 | B | K |
            // | M | 2 | I | E | 
            // | E | 8 | T | Y |
            
            // Taking the last column gives us:
            //
            // |   |
            // | K |
            // | E |
            // | Y |

            // Bumping it up and then moving the top to the bottom and then putting it
            // through the s-box gives us:

            // | K | = | 53 | => | S-Box | => | B3 |
            // | E | = | 45 | => | S-Box | => | 6E |
            // | Y | = | 59 | => | S-Box | => | CB |
            // |   | = | 20 | => | S-Box | => | B7 |

            // Adding in the first round constant gives us:

            // | B3 | ⊕ | 01 | => | B2 |
            // | 6E | ⊕ | 00 | => | 6E |
            // | CB | ⊕ | 00 | => | CB |
            // | B7 | ⊕ | 00 | => | B7 |

            // Now, we xor that with the column from 4 columns ago (e.g. the first column of the 
            // initial round key)

            // | S | = | 53 | ⊕ | B2 | = | E1 |
            // | O | = | 4F | ⊕ | 6E | = | 21 |
            // | M | = | 4D | ⊕ | CB | = | 86 |
            // | E | = | 45 | ⊕ | B7 | = | F2 |

            // This means the first column of the next round key is:
            // | E1 |
            // | 21 |
            // | 86 |
            // | F2 |

            // Now, to calculate the next column, we just xor the previous column with the
            // one from 4 columns ago:

            // |   | = | 20 | ⊕ | E1 | = | C1 |
            // | 1 | = | 31 | ⊕ | 21 | = | 10 | 
            // | 2 | = | 32 | ⊕ | 86 | = | B4 |
            // | 8 | = | 38 | ⊕ | F2 | = | CA |

            // So the second column is
            // | C1 |
            // | 10 | 
            // | B4 |
            // | CA |

            // The third and fourth column are computed similarly. The next round key starts
            // the process over again with a new round key (02) and the process continues until
            // all round keys are made.
                        
            // (Note: For keys bigger than 192 bits, you put every 4th column through the s-box first.)

            for (int col = keyMatrix.Columns; col < allRoundKeys.Columns; col++)
            {
                if ((col%keyMatrix.Columns) == 0)
                {
                    // Most of the work is when we're starting a new round key
                    byte roundConstant = roundConstants[col/keyMatrix.Columns];

                    // The upper left byte is xor'd with the round constant to prevent symmetry
                    allRoundKeys[0, col] =
                        (byte)
                        (allRoundKeys[0, col - keyMatrix.Columns] ^ SubstitutionBox.Value(allRoundKeys[1, col - 1]) ^ roundConstant);

                    for (int row = 1; row < Constants.StateRows; row++)
                    {
                        allRoundKeys[row, col] =
                            (byte)
                            (allRoundKeys[row, col - keyMatrix.Columns] ^
                             SubstitutionBox.Value(allRoundKeys[(row + 1)%Constants.StateRows, col - 1]));
                    }
                }
                else
                {
                    // Special case if we have bigger than a 192 bit key
                    if (((col%keyMatrix.Columns) == Constants.StateRows) && (keyMatrix.Columns > 6))
                    {
                        for (int row = 0; row < Constants.StateRows; row++)
                        {
                            allRoundKeys[row, col] =
                                (byte)
                                (allRoundKeys[row, col - keyMatrix.Columns] ^
                                 SubstitutionBox.Value(allRoundKeys[row, col - 1]));
                        }
                    }
                    else
                    {
                        for (int row = 0; row < Constants.StateRows; row++)
                        {
                            allRoundKeys[row, col] =
                                (byte) (allRoundKeys[row, col - keyMatrix.Columns] ^ allRoundKeys[row, col - 1]);
                        }
                    }
                }
            }

            // The actual round keys are just subsets of allRoundKeys (aka "W")
            for (int currentRoundKey = 0; currentRoundKey < roundKeys.Length; currentRoundKey++)
            {
                roundKeys[currentRoundKey] = allRoundKeys.SubMatrix(plaintextBlockSizeColumns*currentRoundKey,
                                                                    plaintextBlockSizeColumns);
            }

            _RoundKeys = roundKeys;

            if (Debugging.IsEnabled)
            {
                Debugging.Trace("Re-keyed Rijndael with {0}-bit key for {1} bit blocks. Key is:", key.Length * Constants.BitsPerByte, plaintextBlockSizeInBytes * Constants.BitsPerByte);
                ByteUtilities.WriteBytes(key);
                Debugging.Trace("");
                Debugging.Trace("There are {0} round keys.", _RoundKeys.Length);

                for(int i = 0; i < _RoundKeys.Length; i++)
                {
                    Debugging.Trace("Round key {0}:", i);
                    Debugging.Trace(_RoundKeys[i].ToString());
                }
            }
        }
    }
}