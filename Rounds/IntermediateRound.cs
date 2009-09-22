using Moserware.AesIllustrated.Layers;

namespace Moserware.AesIllustrated.Rounds
{
    /// <summary>
    /// The main round function ρ(x) = ⊕(θ(π(γ(x)))).
    /// </summary>
    internal class IntermediateRound : Round
    {
        public IntermediateRound(Settings settings, KeySchedule keySchedule)
            : base(new SubBytes(settings),
                   new ShiftRows(settings),
                   new MixColumns(settings),
                   new AddRoundKey(settings, keySchedule))
        {
        }
    }
}