namespace Moserware.AesIllustrated.Layers
{
    /// <summary>
    /// Represents a single round operation (aka "layer")
    /// </summary>
    internal abstract class Layer
    {
        protected Layer(Settings settings)
        {
            Settings = settings;
        }

        protected Settings Settings { get; private set; }

        public virtual void ApplyLayer(State state, int round)
        {
            ApplyLayer(state);
        }

        protected virtual void ApplyLayer(State state)
        {
            // NOP - override as needed
        }
        
        public virtual void InverseLayer(State state, int round)
        {
            InverseLayer(state);
        }

        protected virtual void InverseLayer(State state)
        {
            // NOP - override as needed
        }

        public override string ToString()
        {
            return GetType().Name;
        }
    }
}