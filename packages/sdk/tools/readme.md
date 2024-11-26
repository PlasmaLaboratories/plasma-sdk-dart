# Analyze Immutables Tool

`analyze_immutables.dart` is a tool designed to ensure that newly added `ContainsImmutable` objects are correctly handled in the `apply` method. This serves as a sanity check for the project.


## How to Use

1. **Setup**: Ensure you have the pub packages updated
2. **File Path**: cd into the tools folder.
3. **Run the Script**: Execute the script using the following command:
   ```sh
   dart run analyze_immutables.dart
   ```

## Output

The script will output the following sections:
1. **Factory Methods**: Lists all factory methods found in the `ContainsImmutable` class.
2. **Types Handled in apply**: Lists all types that are handled in the `apply` matcher.
3. **Factory Methods Not Handled in apply**: Lists factory methods that are not handled in the `apply` method.
4. **Not Handled but Accounted For**: Lists factory methods that are not handled in the `apply` method but are known exceptions.