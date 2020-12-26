namespace Datagrammer.Quic.Protocol.Tls
{
    public static class UnknownHandshake
    {
        public static void SliceBytes(MemoryCursor cursor)
        {
            HandshakeType.Parse(cursor);
            HandshakeLength.SliceBytes(cursor);
        }
    }
}
