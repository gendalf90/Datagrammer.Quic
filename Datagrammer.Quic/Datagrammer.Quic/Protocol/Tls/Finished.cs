using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Finished
    {
        public Finished(ReadOnlyMemory<byte> verifyData)
        {
            VerifyData = verifyData;
        }

        public ReadOnlyMemory<byte> VerifyData { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out Finished result, out ReadOnlyMemory<byte> remainings)
        {
            result = new Finished();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = HandshakeType.Parse(bytes, out var afterTypeBytes);

            if (type != HandshakeType.Finished)
            {
                return false;
            }

            var body = HandshakeLength.SliceHandshakeBytes(afterTypeBytes, out var afterBodyBytes);
            
            result = new Finished(body);
            remainings = afterBodyBytes;

            return true;
        }

        public static HandshakeLength.WritingContext StartWriting(ref Span<byte> destination)
        {
            HandshakeType.Finished.WriteBytes(ref destination);

            return HandshakeLength.StartWriting(ref destination);
        }
    }
}
