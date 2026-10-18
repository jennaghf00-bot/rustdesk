import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'private_binding_receipt.dart';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/utils/http_service.dart' as http;

class PrivateDeviceConfig {
  final String remoteId;
  final String unattendedPassword;
  final String settingsPassword;
  final String hbbsAddress;
  final String hbbrAddress;
  final String serverKey;
  final String serverAddress;

  PrivateDeviceConfig({
    required this.remoteId,
    required this.unattendedPassword,
    required this.settingsPassword,
    required this.hbbsAddress,
    required this.hbbrAddress,
    required this.serverKey,
    required this.serverAddress,
  });

  factory PrivateDeviceConfig.fromJson(Map<String, dynamic> json) {
    return PrivateDeviceConfig(
      remoteId: json['remoteId'] as String? ?? '',
      unattendedPassword: json['unattendedPassword'] as String? ?? '',
      settingsPassword: json['settingsPassword'] as String? ?? '',
      hbbsAddress: json['hbbsAddress'] as String? ?? '',
      hbbrAddress: json['hbbrAddress'] as String? ?? '',
      serverKey: json['serverKey'] as String? ?? '',
      serverAddress: json['serverAddress'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
        'remoteId': remoteId,
        'unattendedPassword': unattendedPassword,
        'settingsPassword': settingsPassword,
        'hbbsAddress': hbbsAddress,
        'hbbrAddress': hbbrAddress,
        'serverKey': serverKey,
        'serverAddress': serverAddress,
      };
}

const String kPrivateClientModeOption = 'private-client-mode';
const String kPrivateClientModeControlled = 'controlled';
const bool kPrivateControlledClientByDefault = true;
const String kPrivateAppName = '\u4f17\u535a\u4fe1AOI\u8fdc\u7a0b\u8fde\u63a5';
const String kPrivateInlineActivationPrefix = '--zbxcfg-';
const String kPrivateInlineActivationEnvKey =
    'RUSTDESK_PRIVATE_INLINE_ACTIVATION';
const String kPrivateInlineActivationFileMarker =
    '\nRUSTDESK_PRIVATE_INLINE_ACTIVATION_V1:';
const String kPrivateForcedRemoteIdOption = 'private-forced-remote-id';

class PrivateInlineActivation {
  final String apiBase;
  final String code;
  final PrivateDeviceConfig? deviceConfig;

  PrivateInlineActivation({
    required this.apiBase,
    required this.code,
    this.deviceConfig,
  });
}

bool isPrivateControlledClient() {
  final mode = bind.mainGetLocalOption(key: kPrivateClientModeOption);
  if (mode.isEmpty) return kPrivateControlledClientByDefault;
  return mode == kPrivateClientModeControlled;
}

Future<bool> applyPrivateProvisionIfPresent() async {
  if (!bind.mainIsInstalled()) return isPrivateControlledClient();

  // Installed service startup applies its protected sidecar. Opening the GUI is read-only.
  final receipt = PrivateServiceReceipt.decode(
    await bind.mainPrivateBindingReceipt(),
  );
  if (receipt.persisted && receipt.actualId.isNotEmpty) {
    await bind.mainSetLocalOption(
      key: kPrivateForcedRemoteIdOption,
      value: receipt.actualId,
    );
  }
  return isPrivateControlledClient();
}

Future<bool> stagePrivateProvisionForInstalledClient(String installPath) async {
  final activation = loadPrivateInlineActivationFromExecutable();
  if (activation == null) return false;
  final apiBase = normalizePrivateApiBase(activation.apiBase);
  final config =
      await resolvePrivateInlineActivationConfig(activation, apiBase);
  final staged = await bind.mainStagePrivateProvision(
    requestJson: jsonEncode({'apiBase': apiBase, ...config.toJson()}),
    installPath: installPath,
  );
  if (!staged) throw Exception('Failed to stage private install provision');
  if (config.settingsPassword.isNotEmpty) {
    await bind.mainSetLocalOption(
      key: kPrivateSettingsPasswordOption,
      value: config.settingsPassword,
    );
  }
  return true;
}

Future<PrivateDeviceConfig> resolvePrivateInlineActivationConfig(
  PrivateInlineActivation inlineActivation,
  String apiBase,
) async {
  try {
    return await consumePrivateBindingCode(apiBase, inlineActivation.code);
  } catch (error) {
    final embeddedConfig = inlineActivation.deviceConfig;
    if (embeddedConfig == null) rethrow;
    debugPrint(
      'failed to consume inline activation code; using embedded config fallback: $error',
    );
    return embeddedConfig;
  }
}

PrivateInlineActivation? loadPrivateInlineActivationFromExecutable() {
  final envPayload = Platform.environment[kPrivateInlineActivationEnvKey];
  final envActivation = decodePrivateInlineActivationPayload(envPayload);
  if (envActivation != null) return envActivation;

  final filePayload = loadPrivateInlineActivationPayloadFromExecutableBytes();
  final fileActivation = decodePrivateInlineActivationPayload(filePayload);
  if (fileActivation != null) return fileActivation;

  try {
    final executable = Platform.resolvedExecutable;
    final normalized = executable.replaceAll('\\', '/');
    final fileName = normalized.substring(normalized.lastIndexOf('/') + 1);
    final markerIndex = fileName.lastIndexOf(kPrivateInlineActivationPrefix);
    if (markerIndex < 0 || !fileName.toLowerCase().endsWith('.exe')) {
      return null;
    }
    final payloadWithExt = fileName.substring(
      markerIndex + kPrivateInlineActivationPrefix.length,
    );
    final payload = payloadWithExt.substring(0, payloadWithExt.length - 4);
    return decodePrivateInlineActivationPayload(payload);
  } catch (_) {
    return null;
  }
}

PrivateInlineActivation? decodePrivateInlineActivationPayload(String? payload) {
  if (payload == null || payload.trim().isEmpty) return null;
  try {
    final decoded = utf8.decode(
      base64Url.decode(base64Url.normalize(payload.trim())),
    );
    final json = jsonDecode(decoded);
    if (json is! Map<String, dynamic>) return null;
    final apiBase = (json['apiBase'] as String? ?? '').trim();
    final code = (json['code'] as String? ?? '').trim();
    if (apiBase.isEmpty || code.isEmpty) return null;
    final deviceConfig = PrivateDeviceConfig.fromJson(json);
    return PrivateInlineActivation(
      apiBase: apiBase,
      code: code,
      deviceConfig: deviceConfig.remoteId.isEmpty ? null : deviceConfig,
    );
  } catch (_) {
    return null;
  }
}

String? loadPrivateInlineActivationPayloadFromExecutableBytes() {
  try {
    final bytes = File(Platform.resolvedExecutable).readAsBytesSync();
    final marker = utf8.encode(kPrivateInlineActivationFileMarker);
    final index = lastIndexOfBytes(bytes, marker);
    if (index < 0) return null;
    final payloadBytes = bytes.sublist(index + marker.length);
    final payload = utf8.decode(payloadBytes, allowMalformed: true).trim();
    return payload.isEmpty ? null : payload;
  } catch (_) {
    return null;
  }
}

int lastIndexOfBytes(List<int> haystack, List<int> needle) {
  if (needle.isEmpty || haystack.length < needle.length) return -1;
  for (var i = haystack.length - needle.length; i >= 0; i--) {
    var matches = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        matches = false;
        break;
      }
    }
    if (matches) return i;
  }
  return -1;
}

void showPrivateDeviceBindingDialog() {
  final apiController = TextEditingController();
  final codeController = TextEditingController();
  var message = '';
  var isInProgress = false;

  gFFI.dialogManager.show((setState, close, context) {
    Future<void> submit() async {
      final apiBase = normalizePrivateApiBase(apiController.text.trim());
      final code = codeController.text.trim();

      if (apiBase.isEmpty || code.isEmpty) {
        setState(() {
          message = 'API 鍦板潃鍜岀粦瀹氱爜涓嶈兘涓虹┖';
        });
        return;
      }

      setState(() {
        message = '';
        isInProgress = true;
      });

      try {
        final config = await consumePrivateBindingCode(apiBase, code);
        var idStatus = await applyPrivateDeviceConfig(apiBase, config);
        while (idStatus == 'provision_authorization_required') {
          final authorization = await requestPrivateBindingAuthorization();
          if (authorization == null) break;
          idStatus = await applyPrivateDeviceConfig(
            apiBase,
            config,
            authorization: authorization,
          );
        }
        if (idStatus.isNotEmpty) {
          setState(() {
            isInProgress = false;
            message = translate(idStatus);
          });
          return;
        }

        await gFFI.serverModel.fetchID();
        await gFFI.serverModel.updatePasswordModel();
        showToast('缁戝畾鎴愬姛');
        close();
      } catch (error) {
        setState(() {
          isInProgress = false;
          message = error.toString();
        });
      }
    }

    return CustomAlertDialog(
      title: Text('缁戝畾浼佷笟璁惧'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: apiController,
            decoration: const InputDecoration(
              labelText: '绠＄悊鍚庡彴 API',
              hintText: 'http://rustdesk-console.example.com',
            ),
          ).workaroundFreezeLinuxMint(),
          const SizedBox(height: 12),
          TextField(
            controller: codeController,
            decoration: const InputDecoration(
              labelText: 'Binding code',
              hintText: 'ABCD-2345',
            ),
          ).workaroundFreezeLinuxMint(),
          if (message.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(message, style: const TextStyle(color: Colors.redAccent)),
          ],
          if (isInProgress) ...[
            const SizedBox(height: 12),
            const LinearProgressIndicator(),
          ],
        ],
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('OK', onPressed: isInProgress ? null : submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

Future<String?> requestPrivateBindingAuthorization() {
  final result = Completer<String?>();
  final controller = TextEditingController();
  gFFI.dialogManager.show((setState, close, context) {
    void finish(String? password) {
      if (!result.isCompleted) result.complete(password);
      close();
    }

    return CustomAlertDialog(
      title: const Text('Secondary password'),
      content: TextField(
        controller: controller,
        obscureText: true,
        autofocus: true,
        decoration: const InputDecoration(labelText: 'Secondary password'),
      ).workaroundFreezeLinuxMint(),
      actions: [
        dialogButton('Cancel', onPressed: () => finish(null), isOutline: true),
        dialogButton('OK', onPressed: () => finish(controller.text)),
      ],
      onSubmit: () => finish(controller.text),
      onCancel: () => finish(null),
    );
  });
  return result.future.whenComplete(controller.dispose);
}

Future<PrivateDeviceConfig> consumePrivateBindingCode(
  String apiBase,
  String code,
) async {
  final base = apiBase.endsWith('/')
      ? apiBase.substring(0, apiBase.length - 1)
      : apiBase;
  final response = await http.post(
    Uri.parse('$base/api/bindings/consume'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({
      'code': code,
      'clientVersion': 'private-rustdesk',
      'operatingSystem': Platform.operatingSystem,
    }),
  );

  if (response.statusCode != 200) {
    throw Exception(bindingErrorMessage(response.body));
  }

  return PrivateDeviceConfig.fromJson(
    jsonDecode(response.body) as Map<String, dynamic>,
  );
}

String normalizePrivateApiBase(String apiBase) {
  var normalized = apiBase.trim();
  while (normalized.endsWith('/')) {
    normalized = normalized.substring(0, normalized.length - 1);
  }
  const bindingPath = '/api/bindings/consume';
  if (normalized.endsWith(bindingPath)) {
    normalized =
        normalized.substring(0, normalized.length - bindingPath.length);
  }
  if (normalized.endsWith('/api')) {
    normalized = normalized.substring(0, normalized.length - 4);
  }
  return normalized;
}

String bindingErrorMessage(String body) {
  try {
    final decoded = jsonDecode(body);
    if (decoded is Map<String, dynamic> && decoded['error'] is String) {
      return decoded['error'] as String;
    }
  } catch (_) {
    // Keep the client-side message stable when the endpoint returns plain text.
  }
  return '缁戝畾澶辫触';
}

Future<String> applyPrivateDeviceConfig(
  String apiBase,
  PrivateDeviceConfig config, {
  String authorization = '',
}) async {
  final status = await verifyPrivateBinding(
    expectedId: config.remoteId,
    apply: () => bind.mainApplyPrivateProvision(
      requestJson: jsonEncode({
        'apiBase': apiBase,
        ...config.toJson(),
        'authorization': authorization,
      }),
    ),
    readReceipt: () => bind.mainPrivateBindingReceipt(),
  );
  if (status.isEmpty || status == 'configured_offline') {
    final receipt = PrivateServiceReceipt.decode(
      await bind.mainPrivateBindingReceipt(),
    );
    if (receipt.persisted && receipt.actualId == config.remoteId) {
      await bind.mainSetLocalOption(
        key: kPrivateForcedRemoteIdOption,
        value: receipt.actualId,
      );
      if (config.settingsPassword.isNotEmpty) {
        await bind.mainSetLocalOption(
          key: kPrivateSettingsPasswordOption,
          value: config.settingsPassword,
        );
      }
      await gFFI.serverModel.fetchID();
    }
  }
  return status;
}

const String kPrivateSettingsPasswordOption = 'private-settings-password';

bool hasPrivateSettingsPassword() {
  return bind
      .mainGetLocalOption(key: kPrivateSettingsPasswordOption)
      .isNotEmpty;
}

bool isPrivateSettingsPasswordValid(String password) {
  return password ==
      bind.mainGetLocalOption(key: kPrivateSettingsPasswordOption);
}

void verifyPrivateSettingsPassword({
  required String title,
  required VoidCallback onVerified,
}) {
  final controller = TextEditingController();
  var message = '';

  gFFI.dialogManager.show((setState, close, context) {
    void submit() {
      if (isPrivateSettingsPasswordValid(controller.text)) {
        close();
        onVerified();
        return;
      }
      setState(() {
        message = 'Invalid secondary password';
      });
    }

    return CustomAlertDialog(
      title: Text(title),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: controller,
            obscureText: true,
            decoration: const InputDecoration(labelText: '浜岀骇瀵嗙爜'),
          ).workaroundFreezeLinuxMint(),
          if (message.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(message, style: const TextStyle(color: Colors.redAccent)),
          ],
        ],
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('OK', onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}
