namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRange
    {
        internal AckRange(bool isAck,
                          bool isGap,
                          ulong length)
        {
            IsAck = isAck;
            IsGap = isGap;
            Length = length;
        }

        public bool IsAck { get; }

        public bool IsGap { get; }

        public ulong Length { get; }
    }
}
