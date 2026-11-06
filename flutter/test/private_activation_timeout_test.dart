import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/private_device_binding.dart';

void main() {
  test('stalled activation uses the existing embedded device config', () async {
    final embedded = PrivateDeviceConfig(
      remoteId: 'ZBX-FIXTURE',
      unattendedPassword: 'fixture-password-only',
      settingsPassword: 'fixture-settings-only',
      hbbsAddress: '127.0.0.1:21116',
      hbbrAddress: '127.0.0.1:21117',
      serverKey: 'fixture-public-key-only',
      serverAddress: '127.0.0.1',
    );
    final stalled = Completer<PrivateDeviceConfig>();
    var requests = 0;
    final pending = resolvePrivateInlineActivationConfig(
      PrivateInlineActivation(
          apiBase: 'http://127.0.0.1', code: 'fixture', deviceConfig: embedded),
      'http://127.0.0.1',
      consume: (_, __) {
        requests++;
        return stalled.future;
      },
      timeout: const Duration(milliseconds: 10),
    );
    final resolved = await pending.timeout(const Duration(seconds: 1));
    expect(identical(resolved, embedded), isTrue);
    expect(requests, 1);
    stalled.complete(embedded);
  });

  test('activation timeout without an embedded config remains an error',
      () async {
    final stalled = Completer<PrivateDeviceConfig>();
    await expectLater(
      resolvePrivateInlineActivationConfig(
        PrivateInlineActivation(apiBase: 'http://127.0.0.1', code: 'fixture'),
        'http://127.0.0.1',
        consume: (_, __) => stalled.future,
        timeout: const Duration(milliseconds: 10),
      ),
      throwsA(isA<TimeoutException>()),
    );
  });
}
