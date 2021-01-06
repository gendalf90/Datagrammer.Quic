namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRange
    {
        public AckRange(bool isAck, bool isGap, int length)
        {
            

            IsGap = isGap;
            IsAck = isAck;
            Length = length;
        }

        public bool IsAck { get; }

        public bool IsGap { get; }

        public int Length { get; }
    }
}
