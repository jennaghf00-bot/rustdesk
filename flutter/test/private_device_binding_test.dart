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

  test('private binding restarts service after successful id change', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    final successCheck = source.indexOf('if (changedId == config.remoteId)');
    expect(successCheck, isNot(-1));

    final successReturn = source.indexOf("return '';", successCheck);
    expect(successReturn, isNot(-1));

    final successBody = source.substring(successCheck, successReturn);
    expect(successBody, contains('restartPrivateRustDeskService()'));
    expect(successBody, contains('gFFI.serverModel.fetchID()'));
  });

  test('private provision is loaded from the application working directory', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();

    expect(source, contains('rustdesk-private-provision.json'));
    expect(source, contains('Directory.current.path'));
    expect(source, contains('applyPrivateProvisionIfPresent'));
    expect(source, contains('private-client-mode'));
  });

  test('private provision is also loaded from windows profile directories', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();

    expect(source, contains('Platform.environment'));
    expect(source, contains('APPDATA'));
    expect(source, contains('LOCALAPPDATA'));
    expect(source, contains('Programs'));
    expect(source, contains('ProgramFiles'));
  });
}
