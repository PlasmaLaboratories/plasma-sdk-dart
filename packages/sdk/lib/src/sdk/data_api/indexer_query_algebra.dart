import 'package:grpc/grpc_connection_interface.dart';
import 'package:plasma_protobuf/plasma_protobuf.dart';

/// Defines a Indexer Query API for interacting with a Indexer node.
class IndexerQueryAlgebra {
  IndexerQueryAlgebra(this.channel)
      : client = TransactionServiceClient(channel);

  /// The gRPC channel to the node.
  final ClientChannelBase channel;

  /// The client stub for the transaction rpc service
  final TransactionServiceClient client;

  /// Query and retrieve a set of UTXOs encumbered by the given LockAddress.
  ///
  /// [fromAddress] The lock address to query the unspent UTXOs by.
  /// [txoState] The state of the UTXOs to query. By default, only unspent UTXOs are returned.
  /// returns A sequence of UTXOs.
  Future<List<Txo>> queryUtxo(
      {required LockAddress fromAddress,
      TxoState txoState = TxoState.UNSPENT}) async {
    final response = await client.getTxosByLockAddress(
      QueryByLockAddressRequest(address: fromAddress, state: txoState),
    );

    return response.txos;
  }
}
