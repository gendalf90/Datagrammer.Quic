using System;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct KeyShareEntry
    {
        private readonly NamedGroup group;
        private readonly ReadOnlyMemory<byte> key;

        public KeyShareEntry(NamedGroup group, ReadOnlyMemory<byte> key)
        {
            this.group = group;
            this.key = key;
        }

        public static KeyShareEntry Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var group = NamedGroup.Parse(bytes, out remainings);
            var key = ByteVector.SliceVectorBytes(remainings, 0..ushort.MaxValue, out remainings);

            return new KeyShareEntry(group, key);
        }

        public KeyShareEntry GeneratePublicKey()
        {
            var publicKey = group.GeneratePublicKey(key);

            return new KeyShareEntry(group, publicKey);
        }

        public void Write(Stream stream)
        {
            group.WriteBytes(stream);

            ByteVector.WriteVector(stream, 0..ushort.MaxValue, key);
        }

        public static KeyShareEntry GeneratePrivateKey(NamedGroup group)
        {
            return new KeyShareEntry(group, group.GeneratePrivateKey());
        }

        public bool HasSameGroup(KeyShareEntry other)
        {
            return group == other.group;
        }
    }
}
