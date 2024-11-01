import 'package:plasma_protobuf/plasma_protobuf.dart';

class TransactionIdSyntax {
  TransactionIdSyntax(this.id);
  final TransactionId id;

  TransactionOutputAddress outputAddress(int network, int ledger, int index) =>
      TransactionOutputAddress(
          network: network, ledger: ledger, index: index, id: id);
}

extension TransactionIdSyntaxExtensions on TransactionId {
  TransactionIdSyntax get syntax => TransactionIdSyntax(this);
}
