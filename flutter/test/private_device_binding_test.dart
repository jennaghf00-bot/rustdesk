import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Architecture guards only. Behavioral receipt tests live in private_binding_receipt_test.dart.
void main() {
  test('periodic ID refresh uses service receipt with an in-flight guard', () {
    final source = File('lib/models/server_model.dart').readAsStringSync();
    final start = source.indexOf('fetchID() async');
    final body = source.substring(start, source.indexOf('\n  }', start));
    expect(body.contains('readServerDisplayId('), isTrue);
    expect(body.contains('mainPrivateBindingReceipt'), isTrue);
    expect(body.contains('isWindows &&'), isTrue);
    expect(body.contains('bind.mainIsInstalled()'), isTrue);
    expect(body.contains('isPrivateControlledClient()'), isTrue);
    expect(body.contains('if (_fetchingId) return;'), isTrue);
    expect(body.contains('finally'), isTrue);
  });

  test('first binding entry does not require the settings password', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    final start = source.indexOf('void showPrivateDeviceBindingDialog()');
    final end = source.indexOf(
        'Future<PrivateDeviceConfig> consumePrivateBindingCode', start);
    expect(start >= 0 && end > start, isTrue);
    final body = source.substring(start, end);
    expect(body.contains('hasPrivateSettingsPassword()'), isFalse);
    expect(body.contains('verifyPrivateSettingsPassword('), isFalse);
  });

  test('controlled mode remains the default', () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    expect(source.contains('kPrivateControlledClientByDefault'), isTrue);
    expect(
        source.contains(
            'if (mode.isEmpty) return kPrivateControlledClientByDefault;'),
        isTrue);
  });

  test(
      'GUI cannot regain cross-profile config writes or restart during binding',
      () {
    final source = File('lib/private_device_binding.dart').readAsStringSync();
    expect(source.contains('persistPrivateDeviceConfigFallback'), isFalse);
    expect(source.contains('writePrivateRemoteIdConfig'), isFalse);
    expect(source.contains('Directory.current'), isFalse);
    expect(source.contains('mainStopService'), isFalse);
    expect(source.contains('mainChangeId'), isFalse);
  });
}
