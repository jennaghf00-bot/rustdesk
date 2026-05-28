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

  test('private binding enforces configured controlled id and retries fallback', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    final functionStart = source.indexOf('Future<String> applyPrivateDeviceConfig(');
    expect(functionStart, isNot(-1));

    final nextFunction = source.indexOf('Future<void> restartPrivateRustDeskService()', functionStart);
    expect(nextFunction, isNot(-1));

    final functionBody = source.substring(functionStart, nextFunction);
    expect(functionBody, contains('mainChangeId'));
    expect(functionBody, contains('persistPrivateRemoteIdFallback'));
    expect(functionBody, contains('mainGetMyId'));
    expect(functionBody, contains('kOptionStopService'));
    expect(functionBody, contains('mainStartService'));
    expect(functionBody, contains('gFFI.serverModel.fetchID()'));
  });

  test('private client defaults to controlled mode without provision json', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();

    expect(source, contains('kPrivateControlledClientByDefault'));
    expect(source, contains('if (mode.isEmpty) return kPrivateControlledClientByDefault;'));
  });

  test('private provision is loaded from the application working directory', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();

    expect(source, contains('rustdesk-private-provision.json'));
    expect(source, contains('--zbxcfg-'));
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

  test('private remote id fallback writes renamed app config paths', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();

    expect(source, contains('kPrivateAppName'));
    expect(source, contains('privateConfigFileCandidates'));
    expect(source, contains(r'\config\'));
    expect(source, contains(r'\$appName.toml'));
    expect(source, contains('ServiceProfiles\\\\LocalService'));
  });
}
