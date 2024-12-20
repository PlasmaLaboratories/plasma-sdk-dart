import 'package:fixnum/fixnum.dart';
import 'package:plasma_protobuf/plasma_protobuf.dart';

abstract class TransactionCostCalculator {
  /// Estimates the cost of including the Transaction in a block.
  /// [transaction] The transaction to cost
  /// returns a bigint value representing the cost
  Int64 costOf(IoTransaction ioTransaction);
}
