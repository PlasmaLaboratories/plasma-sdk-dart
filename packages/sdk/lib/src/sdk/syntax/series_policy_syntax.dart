import 'package:plasma_protobuf/plasma_protobuf.dart';

import '../../crypto/hash/hash.dart';
import '../common/contains_immutable.dart';


/// Provides syntax operations for working with [SeriesPolicy]s.
class SeriesPolicySyntax {
  /// Computes the [GroupId] of the [SeriesPolicy].
  static SeriesId computeId(SeriesPolicy seriesPolicy) {
    final digest = ContainsImmutable.seriesPolicy(seriesPolicy)
        .immutableBytes
        .writeToBuffer();
    final sha256 = SHA256().hash(digest);
    return SeriesId(value: sha256);
  }
}

extension SeriesPolicySyntaxExtension on SeriesPolicy {
  /// Computes the [GroupId] of the [GroupPolicy].
  SeriesId get computeId => SeriesPolicySyntax.computeId(this);
}
