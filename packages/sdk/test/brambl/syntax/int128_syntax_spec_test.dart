import 'package:plasma_protobuf/plasma_protobuf.dart';
import 'package:plasma_sdk/plasma_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('Int128SyntaxSpec', () {
    const mockLong = 100;
    final mockBigInt = BigInt.from(mockLong);
    final mockInt128 = Int128(value: mockBigInt.toUint8List());

    test('int128AsBigInt', () {
      expect(mockInt128.toBigInt(), mockBigInt);
    });

    test('bigIntAsInt128', () {
      expect(Int128(value: mockBigInt.toUint8List()), mockInt128);
    });

    test('longAsInt128', () {
      expect(Int128(value: mockLong.toBytes), mockInt128);
    });
  });
}
