using Moserware.AesIllustrated.Layers;

namespace Moserware.AesIllustrated.Rounds
{
    /// <summary>
    /// The final round, ⊕(π(γ(x))).
    /// </summary>
    internal class FinalRound : Round
    {
        public FinalRound(Settings settings, KeySchedule keySchedule)
            : base(
                new SubBytes(settings),
                new ShiftRows(settings),
                new AddRoundKey(settings, keySchedule)
                )
        {
        }
    }
}