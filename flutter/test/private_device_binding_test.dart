import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('private device binding entry does not require settings password', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    final functionStart = source.indexOf('void showPrivateDeviceBindingDialog()');
    expect(functionStart, isNot(-1));

    final nextFunction = source.indexOf(
      'Future<PrivateDeviceConfig> consumePrivateBindingCode',
      functionStart,
    );
    expect(nextFunction, isNot(-1));

    final functionBody = source.substring(functionStart, nextFunction);
    expect(functionBody, isNot(contains('hasPrivateSettingsPassword()')));
    expect(functionBody, isNot(contains('verifyPrivateSettingsPassword(')));
  });
}
