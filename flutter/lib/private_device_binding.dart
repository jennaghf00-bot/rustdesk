import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
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

class PrivateProvisionConfig {
  final String apiBase;
  final PrivateDeviceConfig deviceConfig;

  PrivateProvisionConfig({
    required this.apiBase,
    required this.deviceConfig,
  });

  factory PrivateProvisionConfig.fromJson(Map<String, dynamic> json) {
    return PrivateProvisionConfig(
      apiBase: json['apiBase'] as String? ?? '',
      deviceConfig: PrivateDeviceConfig.fromJson(json),
    );
  }

  Map<String, dynamic> toJson() => {
        'mode': kPrivateClientModeControlled,
        'appName': kPrivateAppName,
        'apiBase': apiBase,
        ...deviceConfig.toJson(),
      };
}

const String kPrivateProvisionFileName = 'rustdesk-private-provision.json';
const String kPrivateClientModeOption = 'private-client-mode';
const String kPrivateClientModeControlled = 'controlled';
const bool kPrivateControlledClientByDefault = true;
const String kPrivateAppName = '\u4f17\u535a\u4fe1AOI\u8fdc\u7a0b\u8fde\u63a5';
const String kPrivateInlineActivationPrefix = '--zbxcfg-';
const String kPrivateInlineActivationEnvKey =
    'RUSTDESK_PRIVATE_INLINE_ACTIVATION';
const String kPrivateInlineActivationFileMarker =
    '\nRUSTDESK_PRIVATE_INLINE_ACTIVATION_V1:';
const String kPrivateInlineActivationAppliedCodeOption =
    'private-inline-activation-applied-code';

class PrivateInlineActivation {
  final String apiBase;
  final String code;

  PrivateInlineActivation({
    required this.apiBase,
    required this.code,
  });
}

bool isPrivateControlledClient() {
  final mode = bind.mainGetLocalOption(key: kPrivateClientModeOption);
  if (mode.isEmpty) return kPrivateControlledClientByDefault;
  return mode == kPrivateClientModeControlled;
}

Future<bool> applyPrivateProvisionIfPresent() async {
  final inlineActivation = loadPrivateInlineActivationFromExecutable();
  if (inlineActivation != null) {
    final alreadyAppliedCode = bind.mainGetLocalOption(
      key: kPrivateInlineActivationAppliedCodeOption,
    );
    if (alreadyAppliedCode != inlineActivation.code) {
      try {
        final config = await consumePrivateBindingCode(
          normalizePrivateApiBase(inlineActivation.apiBase),
          inlineActivation.code,
        );
        final status = await applyPrivateDeviceConfig(
          normalizePrivateApiBase(inlineActivation.apiBase),
          config,
        );
        if (status.isNotEmpty) {
          debugPrint('failed to apply inline activation payload: $status');
          return false;
        }
        await bind.mainSetLocalOption(
          key: kPrivateInlineActivationAppliedCodeOption,
          value: inlineActivation.code,
        );
        await bind.mainSetLocalOption(
          key: kPrivateClientModeOption,
          value: kPrivateClientModeControlled,
        );
        return true;
      } catch (error) {
        debugPrint('failed to consume inline activation payload: $error');
      }
    }
  }

  final provision = await loadPrivateProvisionConfig();
  if (provision == null) return isPrivateControlledClient();

  final status = await applyPrivateDeviceConfig(
    normalizePrivateApiBase(provision.apiBase),
    provision.deviceConfig,
  );
  if (status.isNotEmpty) {
    debugPrint('failed to apply private provision: $status');
    return false;
  }
  await bind.mainSetLocalOption(
    key: kPrivateClientModeOption,
    value: kPrivateClientModeControlled,
  );
  return true;
}

Future<bool> stagePrivateProvisionForInstalledClient(String installPath) async {
  final inlineActivation = loadPrivateInlineActivationFromExecutable();
  if (inlineActivation == null) return false;

  final apiBase = normalizePrivateApiBase(inlineActivation.apiBase);
  final config =
      await consumePrivateBindingCode(apiBase, inlineActivation.code);
  final provision = PrivateProvisionConfig(
    apiBase: apiBase,
    deviceConfig: config,
  );
  final encoded =
      const JsonEncoder.withIndent('  ').convert(provision.toJson());

  final targets = {
    if (installPath.trim().isNotEmpty)
      '${installPath.trim().replaceAll('/', Platform.pathSeparator)}${Platform.pathSeparator}$kPrivateProvisionFileName',
    ...privateProvisionCandidateFiles().map((file) => file.path),
  };

  var wroteAny = false;
  for (final target in targets) {
    try {
      final file = File(target);
      await file.parent.create(recursive: true);
      await file.writeAsString(encoded);
      wroteAny = true;
    } catch (error) {
      debugPrint('failed to stage private provision at $target: $error');
    }
  }

  return wroteAny;
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
    return PrivateInlineActivation(apiBase: apiBase, code: code);
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

Future<PrivateProvisionConfig?> loadPrivateProvisionConfig() async {
  for (final file in privateProvisionCandidateFiles()) {
    try {
      if (!await file.exists()) continue;
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is Map<String, dynamic>) {
        return PrivateProvisionConfig.fromJson(decoded);
      }
    } catch (error) {
      debugPrint('failed to read private provision ${file.path}: $error');
    }
  }
  return null;
}

List<File> privateProvisionCandidateFiles() {
  final candidates = <String>[
    '${Directory.current.path}${Platform.pathSeparator}$kPrivateProvisionFileName',
  ];
  final executableDir = parentPath(Platform.resolvedExecutable);
  if (executableDir.isNotEmpty) {
    candidates.add(
        '$executableDir${Platform.pathSeparator}$kPrivateProvisionFileName');
  }
  final environment = Platform.environment;
  for (final key in [
    'APPDATA',
    'LOCALAPPDATA',
    'ProgramFiles',
    'ProgramFiles(x86)',
  ]) {
    final root = environment[key];
    if (root == null || root.isEmpty) continue;
    for (final appName in ['RustDesk', kPrivateAppName]) {
      candidates.add(
        '$root${Platform.pathSeparator}$appName${Platform.pathSeparator}$kPrivateProvisionFileName',
      );
    }
    if (key == 'LOCALAPPDATA') {
      for (final appName in ['RustDesk', kPrivateAppName]) {
        candidates.add(
          '$root${Platform.pathSeparator}Programs${Platform.pathSeparator}$appName${Platform.pathSeparator}$kPrivateProvisionFileName',
        );
      }
    }
  }
  return candidates.toSet().map(File.new).toList();
}

String parentPath(String path) {
  final normalized = path.replaceAll('\\', Platform.pathSeparator);
  final index = normalized.lastIndexOf(Platform.pathSeparator);
  if (index <= 0) return '';
  return normalized.substring(0, index);
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
        final idStatus = await applyPrivateDeviceConfig(apiBase, config);
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
  PrivateDeviceConfig config,
) async {
  if (config.remoteId.isEmpty ||
      config.unattendedPassword.isEmpty ||
      config.hbbsAddress.isEmpty) {
    throw Exception('Binding config is incomplete');
  }

  await bind.mainSetOption(key: 'private-management-api', value: apiBase);
  await bind.mainSetOption(
    key: 'custom-rendezvous-server',
    value: config.hbbsAddress,
  );
  await bind.mainSetOption(key: 'relay-server', value: config.hbbrAddress);
  await bind.mainSetOption(key: 'key', value: config.serverKey);
  await bind.mainSetOption(key: kOptionEnablePrivacyMode, value: 'N');
  await bind.mainSetOption(key: kOptionApproveMode, value: 'password');
  await bind.mainSetOption(key: kOptionStopService, value: 'N');
  await bind.mainSetOption(
    key: kOptionVerificationMethod,
    value: kUsePermanentPassword,
  );

  final passwordOk = await bind.mainSetPermanentPasswordWithResult(
    password: config.unattendedPassword,
  );
  if (!passwordOk) {
    throw Exception('Failed to set unattended password');
  }

  if (config.settingsPassword.isNotEmpty) {
    await bind.mainSetLocalOption(
      key: kPrivateSettingsPasswordOption,
      value: config.settingsPassword,
    );
  }

  final currentId = await bind.mainGetMyId();
  if (currentId == config.remoteId) {
    await Future.delayed(const Duration(milliseconds: 300));
    await gFFI.serverModel.fetchID();
    return '';
  }

  bind.mainChangeId(newId: config.remoteId);
  var status = await bind.mainGetAsyncStatus();
  var retries = 0;
  while (status == ' ' && retries < 300) {
    await Future.delayed(const Duration(milliseconds: 100));
    status = await bind.mainGetAsyncStatus();
    retries++;
  }
  if (status == ' ') {
    return 'Timed out while changing controlled ID';
  }

  Future<bool> verifyRemoteId() async {
    await Future.delayed(const Duration(milliseconds: 600));
    final changedId = await bind.mainGetMyId();
    if (changedId == config.remoteId) {
      await gFFI.serverModel.fetchID();
      return true;
    }
    return false;
  }

  if (status.isEmpty && await verifyRemoteId()) {
    return '';
  }

  if (status.isEmpty ||
      status == 'server_not_support' ||
      status == 'Unknown Error') {
    final persisted = await persistPrivateRemoteIdFallback(config.remoteId);
    if (!persisted) {
      return 'Failed to persist controlled ID';
    }
    if (await verifyRemoteId()) {
      return '';
    }
    return 'Controlled ID mismatch after fallback';
  }

  return status;
}

Future<void> restartPrivateRustDeskService() async {
  try {
    await bind.mainStopService();
    await Future.delayed(const Duration(milliseconds: 500));
    await bind.mainStartService();
  } catch (error) {
    debugPrint(
        'failed to restart RustDesk service after private binding: $error');
  }
}

Future<bool> persistPrivateRemoteIdFallback(String remoteId) async {
  if (!Platform.isWindows) return false;

  final appData = Platform.environment['APPDATA'];
  final programData = Platform.environment['PROGRAMDATA'];
  final paths = privateConfigFileCandidates(appData, programData);

  var wroteConfig = false;
  for (final path in paths) {
    try {
      await writePrivateRemoteIdConfig(File(path), remoteId);
      wroteConfig = true;
    } catch (error) {
      debugPrint('failed to persist private remote id at $path: $error');
    }
  }

  if (!wroteConfig) return false;
  return true;
}

List<String> privateConfigFileCandidates(String? appData, String? programData) {
  final paths = <String>[];
  for (final appName in ['RustDesk', kPrivateAppName]) {
    if (appData != null && appData.isNotEmpty) {
      paths.add('$appData\\$appName\\config\\$appName.toml');
    }
    if (programData != null && programData.isNotEmpty) {
      paths.add('$programData\\$appName\\config\\$appName.toml');
    }
    paths.add(
      'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\$appName\\config\\$appName.toml',
    );
  }
  return paths.toSet().toList();
}

Future<void> writePrivateRemoteIdConfig(
    File configFile, String remoteId) async {
  await configFile.parent.create(recursive: true);
  var content = '';
  if (await configFile.exists()) {
    content = await configFile.readAsString();
  }

  final escapedId = remoteId.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  if (RegExp(r'^id\s*=', multiLine: true).hasMatch(content)) {
    content = content.replaceAll(
        RegExp(r'^id\s*=.*$', multiLine: true), 'id = "$escapedId"');
  } else {
    content = content.trimRight();
    content =
        content.isEmpty ? 'id = "$escapedId"' : '$content\r\nid = "$escapedId"';
  }

  if (RegExp(r'^enc_id\s*=', multiLine: true).hasMatch(content)) {
    content = content.replaceAll(
        RegExp(r'^enc_id\s*=.*$', multiLine: true), 'enc_id = ""');
  } else {
    content = '$content\r\nenc_id = ""';
  }

  await configFile.writeAsString('$content\r\n');
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
