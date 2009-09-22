using Moserware.AesIllustrated.Layers;

namespace Moserware.AesIllustrated.Rounds
{
    /// <summary>
    /// Base class for all round functions. 
    /// </summary>
    internal abstract class Round
    {
        private readonly Layer[] _Layers;

        protected Round(params Layer[] layers)
        {
            _Layers = layers;
        }

        /// <summary>
        /// Applies the round in the forward direction (for encryption).
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="keyIndex">The round key index to use.</param>
        public void Apply(State state, int keyIndex)
        {
            // Apply the layers in forward order
            for (int ixLayer = 0; ixLayer < _Layers.Length; ixLayer++)
            {
                _Layers[ixLayer].ApplyLayer(state, keyIndex);

                if(Debugging.IsEnabled)
                {
                    Debugging.Trace("After applying {0} in round {1}, the state is now:", _Layers[ixLayer], keyIndex);
                    Debugging.Trace(state.ToString());
                }
            }
        }

        /// <summary>
        /// Applies the round in the reverse direction (for decryption).
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="keyIndex">The round key index to use.</param>
        public void Inverse(State state, int keyIndex)
        {
            // Apply the layers in reverse order
            for (int ixLayer = _Layers.Length - 1; ixLayer >= 0; ixLayer--)
            {
                _Layers[ixLayer].InverseLayer(state, keyIndex);

                if (Debugging.IsEnabled)
                {
                    Debugging.Trace("After applying {0} in round {1}, the state is now:", _Layers[ixLayer].ToString());
                    Debugging.Trace(state.ToString());
                }
            }
        }
    }
}