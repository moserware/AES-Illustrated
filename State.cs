namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Stores the state of the cipher.
    /// </summary>
    internal class State : ByteMatrix
    {
        public State(byte[] inputBytes)
            : base(Constants.StateRows, inputBytes)
        {
        }
    }
}