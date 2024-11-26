// ignore_for_file: avoid_print

import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

void main() {
  const filePath = '../lib/src/sdk/common/contains_immutable.dart';
  final fileContent = _readFileContent(filePath);

  final parseResult = parseString(content: fileContent);
  final compilationUnit = parseResult.unit;

  final factoryMethods = <String, String>{};
  final applyTypes = <String>{};


  /// Exceptions to this analyzer that shouldn't matter
  final exceptions = {
    'empty': 'No parameters',
    'record': '(dynamic, dynamic)',
    'pair': '(dynamic, dynamic)',
    'nullable': 'ContainsImmutable?',
    'nullableTest': 'bool',
  };


  compilationUnit.visitChildren(_FactoryConstructorVisitor(factoryMethods));
  compilationUnit.visitChildren(_ApplyTypeVisitor(applyTypes));

  _printFactoryMethods(factoryMethods);
  _printApplyTypes(applyTypes);
  _printNotHandledFactoryMethods(factoryMethods, applyTypes, exceptions);
  _printAccountedForFactoryMethods(factoryMethods, exceptions);
}

/// Reads the content of the file at the given [filePath].
String _readFileContent(String filePath) {
  try {
    return File(filePath).readAsStringSync();
  } catch (e) {
    print('Error reading file: $e');
    rethrow;
  }
}

/// Prints the factory methods.
void _printFactoryMethods(Map<String, String> factoryMethods) {
  print('Factory Methods:');
  if (factoryMethods.isEmpty) {
    print('No factory methods found.');
  } else {
    factoryMethods.forEach((name, type) {
      print('- $name: $type');
    });
  }
}

/// Prints the types handled in the apply method.
void _printApplyTypes(Set<String> applyTypes) {
  print('\nTypes Handled in apply:');
  if (applyTypes.isEmpty) {
    print('No types handled in apply.');
  } else {
    for (final type in applyTypes) {
      print('- $type');
    }
  }
}

/// Prints the factory methods not handled in the apply method.
void _printNotHandledFactoryMethods(
  Map<String, String> factoryMethods,
  Set<String> applyTypes,
  Map<String, String> exceptions,
) {
  print('\nFactory Methods Not Handled in apply:');
  var notHandled = false;
  factoryMethods.forEach((name, type) {
    if (!applyTypes.contains(type) && !exceptions.containsKey(name)) {
      print('- $name: $type');
      notHandled = true;
    }
  });
  if (!notHandled) {
    print('All factory methods are handled in apply.');
  }
}

/// Prints the factory methods not handled in the apply method but are accounted for as exceptions.
void _printAccountedForFactoryMethods(
  Map<String, String> factoryMethods,
  Map<String, String> exceptions,
) {
  print('\nFactory methods Not handled in apply, but are exceptions:');
  var accountedFor = false;
  factoryMethods.forEach((name, type) {
    if (exceptions.containsKey(name)) {
      print('- $name: $type');
      accountedFor = true;
    }
  });
  if (!accountedFor) {
    print('No factory methods are accounted for as exceptions.');
  }
}

class _FactoryConstructorVisitor extends RecursiveAstVisitor<void> {
  _FactoryConstructorVisitor(this.factoryMethods);
  final Map<String, String> factoryMethods;

  @override
  void visitConstructorDeclaration(ConstructorDeclaration node) {
    if (node.factoryKeyword != null) {
      final name = node.name.toString();
      final firstParameterType = node.parameters.parameters.isNotEmpty
          ? node.parameters.parameters.first.childEntities.first.toString()
          : 'No parameters';
      factoryMethods[name] = firstParameterType;
    }
    super.visitConstructorDeclaration(node);
  }
}

class _ApplyTypeVisitor extends RecursiveAstVisitor<void> {
  _ApplyTypeVisitor(this.applyTypes);
  final Set<String> applyTypes;

  static const _typeRegExp = r'type is ([\w.<>]+)';

  @override
  void visitIfStatement(IfStatement node) {
    final condition = node.expression.toString();
    final match = RegExp(_typeRegExp).firstMatch(condition);
    if (match != null) {
      applyTypes.add(match.group(1)!);
    }
    super.visitIfStatement(node);
  }
}