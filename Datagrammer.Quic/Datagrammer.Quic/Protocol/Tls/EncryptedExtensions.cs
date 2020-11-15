using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class EncryptedExtensions
    {
        public static void WriteEmpty(MemoryCursor cursor)
        {
            HandshakeType.EncryptedExtensions.WriteBytes(cursor);

            using (HandshakeLength.StartWriting(cursor))
            {
                var bytes = cursor.Move(2);

                bytes[0] = 0;
                bytes[1] = 0;
            }
        }

        public static bool TrySlice(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = HandshakeType.Parse(bytes, out var afterTypeBytes);

            if (type != HandshakeType.EncryptedExtensions)
            {
                return false;
            }

            HandshakeLength.SliceHandshakeBytes(afterTypeBytes, out remainings);

            return true;
        }
    }
}
