import 'package:plasma_protobuf/plasma_protobuf.dart';

import '../../crypto/hash/hash.dart';
import '../common/contains_immutable.dart';


/// Provides syntax operations for working with [GroupPolicy]s.
class GroupPolicySyntax {
  /// Computes the [GroupId] of the [GroupPolicy].
  static GroupId computeId(GroupPolicy groupPolicy) {
    final digest = ContainsImmutable.groupPolicy(groupPolicy)
        .immutableBytes
        .writeToBuffer();
    final sha256 = SHA256().hash(digest);
    return GroupId(value: sha256);
  }
}

extension GroupPolicySyntaxExtension on GroupPolicy {
  /// Computes the [GroupId] of the [GroupPolicy].
  GroupId get computeId => GroupPolicySyntax.computeId(this);
}
