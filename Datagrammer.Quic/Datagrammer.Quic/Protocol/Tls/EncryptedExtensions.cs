namespace Datagrammer.Quic.Protocol.Tls
{
    public static class EncryptedExtensions
    {
        public static void WriteEmpty(MemoryCursor cursor)
        {
            HandshakeType.EncryptedExtensions.WriteBytes(cursor);

            using (HandshakeLength.StartWriting(cursor))
            {
                var bytes = cursor.Move(2).Span;

                bytes[0] = 0;
                bytes[1] = 0;
            }
        }

        public static bool TrySlice(MemoryCursor cursor)
        {
            if(!HandshakeType.TrySlice(cursor, HandshakeType.EncryptedExtensions))
            {
                return false;
            }

            HandshakeLength.SliceBytes(cursor);

            return true;
        }
    }
}
