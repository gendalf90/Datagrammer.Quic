namespace Datagrammer.Quic.Protocol.Packet.TransportParameters
{
    public readonly struct TransportParameter
    {
        public TransportParameter(TransportParameterType type, MemoryBuffer data)
        {
            Type = type;
            Data = data;
        }

        public TransportParameterType Type { get; }

        public MemoryBuffer Data { get; }

        public static bool TryParse(MemoryCursor cursor, TransportParameterType type, out TransportParameter result)
        {
            result = new TransportParameter();

            if (!TransportParameterType.TrySlice(cursor, type))
            {
                return false;
            }

            var data = PacketPayload.SlicePacketBytes(cursor);

            result = new TransportParameter(type, data);

            return true;
        }

        public static PacketPayload.CursorWritingContext StartWriting(MemoryCursor cursor, TransportParameterType type)
        {
            type.Write(cursor);

            return PacketPayload.StartPacketWriting(cursor);
        }

        public static void Slice(MemoryCursor cursor)
        {
            TransportParameterType.Parse(cursor);
            PacketPayload.SlicePacketBytes(cursor);
        }
    }
}
