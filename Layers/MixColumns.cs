namespace Moserware.AesIllustrated.Layers
{
    /// <summary>
    /// Performs the mix columns diffusion (linear) step (θ).
    /// </summary>
    internal class MixColumns : Layer
    {
        public MixColumns(Settings settings)
            : base(settings)
        {
        }

        protected override void ApplyLayer(State state)
        {
            byte[] tempVector = new byte[4];

            for (int col = 0; col < state.Columns; col++)
            {
                ByteMatrixColumn currentColumn = state.GetColumn(col);

                // Multiply each column by c(x) which is defined as 
                // c(x) = 03*x^3 ⊕ 01*x^2 ⊕ 01*x ⊕ 02;

                // This is the same as multiplication by this matrix:
                // | 02 03 01 01 |   | x0 |
                // | 01 02 03 01 |   | x1 |
                // | 01 01 02 03 | * | x2 |
                // | 03 01 01 02 |   | x3 |

                // We can perform this multiply by starting with the top row of the matrix:
                // [02 03 01 01] and keep rotating it by 1 each column. Note that the multiply
                // is in the Rijndael field.
                for (int row = 0; row < 4; row++)
                {
                    tempVector[row] = (byte) (
                                                 FiniteFieldMath.Multiply(0x02, currentColumn[row]) ^
                                                 FiniteFieldMath.Multiply(0x03, currentColumn[(row + 1)%4]) ^
                                                 FiniteFieldMath.Multiply(0x01, currentColumn[(row + 2)%4]) ^
                                                 FiniteFieldMath.Multiply(0x01, currentColumn[(row + 3)%4]));
                }

                // Now that we have the result of the multiply in tempVector, we 
                // copy it back to the state matrix:
                for (int row = 0; row < 4; row++)
                {
                    currentColumn[row] = tempVector[row];
                }
            }
        }

        protected override void InverseLayer(State state)
        {
            byte[] tempVector = new byte[4];

            for (int col = 0; col < state.Columns; col++)
            {
                ByteMatrixColumn currentColumn = state.GetColumn(col);

                // Multiply each column by d(x) which is the inverse of c(x). This means:
                // c(x) * d(x) ≡ 1, which expanded is
                // (03*x^3 ⊕ 01*x^2 ⊕ 01*x ⊕ 02) * d(x) ≡ 1

                // After some derivation, we can calculate that 
                // d(x) = 0B*x^3 ⊕ 0D*x^2 ⊕ 09*x ⊕ 0E;

                // This is the same as multiplication by this matrix:
                // | 0E 0B 0D 09 |   | x0 |
                // | 09 0E 0B 0D |   | x1 |
                // | 0D 09 0E 0B | * | x2 |
                // | 0B 0D 09 0E |   | x3 |

                // We can perform this multiply by starting with the top row of the matrix:
                // [0E 0B 0D 09] and keep rotating it by 1 each column. Note that the multiply
                // is in the Rijndael field.

                for (int row = 0; row < 4; row++)
                {
                    tempVector[row] = (byte) (
                                                 FiniteFieldMath.Multiply(0x0E, currentColumn[row]) ^
                                                 FiniteFieldMath.Multiply(0x0B, currentColumn[(row + 1)%4]) ^
                                                 FiniteFieldMath.Multiply(0x0D, currentColumn[(row + 2)%4]) ^
                                                 FiniteFieldMath.Multiply(0x09, currentColumn[(row + 3)%4]));
                }

                // Now that we have the result of the multiply in tempVector, we 
                // copy it back to the state matrix:
                for (int row = 0; row < 4; row++)
                {
                    currentColumn[row] = tempVector[row];
                }
            }
        }
    }
}