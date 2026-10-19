import 'dart:convert';
import 'package:flutter_hbb/private_binding_receipt.dart';
import 'package:flutter_test/flutter_test.dart';

String serviceReceipt({bool persisted = true}) => jsonEncode({
      'version': 1,
      'actualId': 'ZBX-0049',
      'generation': 'generation-49',
      'publicFingerprint': 'fingerprint-49',
      'persisted': persisted,
      'registered': false,
      'phase': 'configured_offline',
      'errorCode': null,
    });

void main() {
  test('installed private display uses saved service ID, even when offline',
      () async {
    var legacyReads = 0;
    final id = await readServerDisplayId(
      serviceOwned: true,
      readReceipt: () async => serviceReceipt(),
      readLegacyId: () async {
        legacyReads++;
        return 'ZBX-0047';
      },
    );
    expect(id, 'ZBX-0049');
    expect(legacyReads, 0);
    expect(PrivateServiceReceipt.decode(serviceReceipt()).validate(id),
        'configured_offline');
  });

  test('next refresh recovers after service startup without using stale ID',
      () async {
    var reads = 0;
    Future<String> read() => readServerDisplayId(
          serviceOwned: true,
          readReceipt: () async => ++reads == 1
              ? '{"errorCode":"private_service_unavailable"}'
              : serviceReceipt(),
          readLegacyId: () async => throw StateError('stale GUI ID was read'),
        );
    expect(await read(), isEmpty);
    expect(await read(), 'ZBX-0049');
  });

  test('invalid or unsaved service identity never falls back to local ID',
      () async {
    for (final json in ['not json', '{}', serviceReceipt(persisted: false)]) {
      expect(
          await readServerDisplayId(
            serviceOwned: true,
            readReceipt: () async => json,
            readLegacyId: () async => 'ZBX-0047',
          ),
          isEmpty);
    }
    expect(
        await readServerDisplayId(
          serviceOwned: true,
          readReceipt: () async => throw StateError('IPC unavailable'),
          readLegacyId: () async => 'ZBX-0047',
        ),
        isEmpty);
  });

  test('non-service-owned display keeps existing getter', () async {
    expect(
        await readServerDisplayId(
          serviceOwned: false,
          readReceipt: () async => throw StateError('unexpected receipt read'),
          readLegacyId: () async => 'legacy-id',
        ),
        'legacy-id');
  });
}
