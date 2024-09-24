import 'package:topl_common/proto/brambl/models/box/value.pb.dart';


/// simplify protobuf imports with these typedefs
/// TODO: replace global occurences with new typedefs

typedef LVL = Value_LVL;
typedef Asset = Value_Asset;
// typedef Value = Value_Value; // TODO: disabled because it overlaps with BoxValue
typedef Group = Value_Group;
typedef Series = Value_Series;
typedef TOPL = Value_TOPL;
typedef UpdateProposal = Value_UpdateProposal;
