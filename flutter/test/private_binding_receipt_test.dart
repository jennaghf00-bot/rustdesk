import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import '../lib/private_binding_receipt.dart';

Map<String, dynamic> receipt({bool registered = true}) => {
      'version': 1,
      'actualId': 'ZBX-TEST',
      'generation': 'generation-1',
      'persisted': true,
      'publicFingerprint': 'public-fingerprint',
      'registered': registered,
      'phase': registered ? 'registered' : 'configured_offline',
      'transport': 'udp',
      'errorCode': null,
    };

void main() {
  test('matching displayed ID without service receipt is not success',
      () async {
    final result = await verifyPrivateBinding(
      expectedId: 'ZBX-TEST',
      apply: () async => jsonEncode({'actualId': 'ZBX-TEST'}),
      readReceipt: () async => jsonEncode({'actualId': 'ZBX-TEST'}),
      attempts: 1,
      delay: () async {},
    );
    expect(result, isNotEmpty);
  });
  test('saved configuration without registration is explicitly offline',
      () async {
    final result = await verifyPrivateBinding(
      expectedId: 'ZBX-TEST',
      apply: () async => jsonEncode(receipt(registered: false)),
      readReceipt: () async => jsonEncode(receipt(registered: false)),
      attempts: 2,
      delay: () async {},
    );
    expect(result, 'configured_offline');
  });
  test('current service registration is required and application runs once',
      () async {
    var applications = 0;
    final result = await verifyPrivateBinding(
      expectedId: 'ZBX-TEST',
      apply: () async {
        applications++;
        return jsonEncode(receipt(registered: false));
      },
      readReceipt: () async => jsonEncode(receipt()),
      attempts: 2,
      delay: () async {},
    );
    expect(result, isEmpty);
    expect(applications, 1);
  });
  test('different ID generation or key never verifies the requested binding',
      () async {
    for (final field in ['actualId', 'generation', 'publicFingerprint']) {
      final changed = receipt();
      changed[field] = 'changed';
      final result = await verifyPrivateBinding(
        expectedId: 'ZBX-TEST',
        apply: () async => jsonEncode(receipt(registered: false)),
        readReceipt: () async => jsonEncode(changed),
        attempts: 1,
        delay: () async {},
      );
      expect(result, isNotEmpty, reason: field);
    }
  });
  test('missing service or incomplete persistence never reports success',
      () async {
    final incomplete = receipt()..['persisted'] = false;
    for (final value in [
      incomplete,
      {'errorCode': 'private_service_unavailable'}
    ]) {
      final result = await verifyPrivateBinding(
        expectedId: 'ZBX-TEST',
        apply: () async => jsonEncode(value),
        readReceipt: () async => jsonEncode(receipt()),
        attempts: 1,
        delay: () async {},
      );
      expect(result, isNotEmpty);
    }
  });
}
