import 'package:fixnum/fixnum.dart';
import 'package:grpc/grpc_connection_interface.dart';
import 'package:plasma_protobuf/plasma_protobuf.dart';

/// Defines a Node Query API for interacting with a Node node.
sealed class NodeQueryAlgbraDefinition {
  /// Fetches a block by its blockheight [height].
  /// Returns the [BlockId], [BlockBody], and contained transactions [IoTransactions] of the fetched block, if it exists.
  Future<(BlockId, BlockBody, List<IoTransaction>)?> blockByHeight(
      Int64 height);

  /// Fetches a block by its [blockId.
  /// Returns a [BlockId], [BlockBody], and List of contained transactions [IoTransactions] of the fetched block, if it exists.
  Future<(BlockId, BlockBody, List<IoTransaction>)?> blockById(BlockId blockId);

  /// Fetches a transaction by its [txId] and returns the fetched transaction, if it exists.
  Future<IoTransaction?> fetchTransaction(TransactionId txId);
}

/// Defines a Node Query API for interacting with a Node node.
class NodeQueryAlgebra implements NodeQueryAlgbraDefinition {
  NodeQueryAlgebra(this.channel) : client = NodeRpcClient(channel);

  /// The gRPC channel to the node.
  final ClientChannelBase channel;

  /// The client stub for the node rpc service
  final NodeRpcClient client;

  @override
  Future<(BlockId, BlockBody, List<IoTransaction>)?> blockByHeight(
      Int64 height) async {
    final req = FetchBlockIdAtHeightReq(height: height);
    final blockId = (await client.fetchBlockIdAtHeight(req)).blockId;

    final response = await blockById(blockId);
    return response;
  }

  @override
  Future<(BlockId, BlockBody, List<IoTransaction>)?> blockById(
      BlockId blockId) async {
    final req = FetchBlockBodyReq(blockId: blockId);
    final body = (await client.fetchBlockBody(req)).body;

    final txIds = body.transactionIds;

    final List<Future<IoTransaction?>> futures =
        txIds.map((id) => fetchTransaction(id)).toList();
    final List<IoTransaction> transactions =
        (await Future.wait(futures)).whereType<IoTransaction>().toList();

    return (blockId, body, transactions);
  }

  @override
  Future<IoTransaction?> fetchTransaction(TransactionId txId) async {
    final req = FetchTransactionReq(transactionId: txId);
    final res = await client.fetchTransaction(req);
    return res.transaction;
  }
}
