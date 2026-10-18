import 'dart:convert';

class PrivateServiceReceipt {
  final Map<String, dynamic> _value;
  PrivateServiceReceipt._(this._value);

  factory PrivateServiceReceipt.decode(String json) {
    try {
      final value = jsonDecode(json);
      if (value is Map<String, dynamic>) return PrivateServiceReceipt._(value);
    } catch (_) {}
    return PrivateServiceReceipt._(
        {'errorCode': 'private_service_receipt_invalid'});
  }

  String get actualId => _value['actualId'] as String? ?? '';
  String get generation => _value['generation'] as String? ?? '';
  String get fingerprint => _value['publicFingerprint'] as String? ?? '';
  bool get persisted => _value['persisted'] == true;

  String validate(String expectedId, {PrivateServiceReceipt? applied}) {
    final error = _value['errorCode'];
    if (error is String && error.isNotEmpty) return error;
    if (_value['version'] != 1 || generation.isEmpty || fingerprint.isEmpty) {
      return 'private_service_receipt_invalid';
    }
    if (!persisted) return 'configuration_incomplete';
    if (actualId != expectedId) return 'private_service_identity_mismatch';
    if (applied != null &&
        (generation != applied.generation ||
            fingerprint != applied.fingerprint)) {
      return 'private_service_identity_mismatch';
    }
    if (_value['registered'] != true || _value['phase'] != 'registered') {
      return 'configured_offline';
    }
    return '';
  }
}

Future<String> verifyPrivateBinding({
  required String expectedId,
  required Future<String> Function() apply,
  required Future<String> Function() readReceipt,
  int attempts = 100,
  Future<void> Function()? delay,
}) async {
  try {
    final applied = PrivateServiceReceipt.decode(await apply());
    var status = applied.validate(expectedId);
    if (status != 'configured_offline') return status;
    for (var i = 0; i < attempts; i++) {
      await (delay?.call() ??
          Future<void>.delayed(const Duration(milliseconds: 300)));
      final current = PrivateServiceReceipt.decode(await readReceipt());
      status = current.validate(expectedId, applied: applied);
      if (status != 'configured_offline') return status;
    }
    return 'configured_offline';
  } catch (_) {
    return 'private_service_unavailable';
  }
}
