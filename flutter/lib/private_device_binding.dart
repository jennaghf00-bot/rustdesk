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
}

const String kPrivateProvisionFileName = 'rustdesk-private-provision.json';
const String kPrivateClientModeOption = 'private-client-mode';
const String kPrivateClientModeControlled = 'controlled';
const bool kPrivateControlledClientByDefault = true;
const String kPrivateAppName = '\u4f17\u535a\u4fe1AOI\u8fdc\u7a0b\u8fde\u63a5';

bool isPrivateControlledClient() {
  final mode = bind.mainGetLocalOption(key: kPrivateClientModeOption);
  if (mode.isEmpty) return kPrivateControlledClientByDefault;
  return mode == kPrivateClientModeControlled;
}

Future<bool> applyPrivateProvisionIfPresent() async {
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
    candidates.add('$executableDir${Platform.pathSeparator}$kPrivateProvisionFileName');
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
              labelText: '缁戝畾鐮?,
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
    normalized = normalized.substring(0, normalized.length - bindingPath.length);
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
  if (config.unattendedPassword.isEmpty ||
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

  await Future.delayed(const Duration(milliseconds: 300));
  await gFFI.serverModel.fetchID();
  return '';
}

Future<void> restartPrivateRustDeskService() async {
  try {
    await bind.mainStopService();
    await Future.delayed(const Duration(milliseconds: 500));
    await bind.mainStartService();
  } catch (error) {
    debugPrint('failed to restart RustDesk service after private binding: $error');
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

  await restartPrivateRustDeskService();
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

Future<void> writePrivateRemoteIdConfig(File configFile, String remoteId) async {
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
        message = '浜岀骇瀵嗙爜涓嶆纭?;
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

