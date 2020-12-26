namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct KeyShareEntry
    {
        public KeyShareEntry(NamedGroup group, MemoryBuffer key)
        {
            Group = group;
            Key = key;
        }

        public NamedGroup Group { get; }

        public MemoryBuffer Key { get; }

        public static KeyShareEntry Parse(MemoryCursor cursor)
        {
            var group = NamedGroup.Parse(cursor);
            var key = ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

            return new KeyShareEntry(group, key);
        }

        public static ByteVector.CursorWritingContext StartWriting(MemoryCursor cursor, NamedGroup group)
        {
            group.WriteBytes(cursor);

            return ByteVector.StartVectorWriting(cursor, 0..ushort.MaxValue);
        }
    }
}
