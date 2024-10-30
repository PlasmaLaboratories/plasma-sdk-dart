import 'package:plasma_sdk/plasma_sdk.dart';

void main() {
  /// encode String to blake2b256
  const input = "Foobar";

  Blake2b256().hash(input.toUtf8Uint8List());
}
