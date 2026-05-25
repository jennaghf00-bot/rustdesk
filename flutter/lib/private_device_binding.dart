import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_hbb/utils/http_service.dart' as http;

class PrivateDeviceConfig {
  final String remoteId;
  final String unattendedPassword;
  final String hbbsAddress;
  final String hbbrAddress;
  final String serverAddress;

  PrivateDeviceConfig({
    required this.remoteId,
    required this.unattendedPassword,
    required this.hbbsAddress,
    required this.hbbrAddress,
    required this.serverAddress,
  });

  factory PrivateDeviceConfig.fromJson(Map<String, dynamic> json) {
    return PrivateDeviceConfig(
      remoteId: json['remoteId'] as String? ?? '',
      unattendedPassword: json['unattendedPassword'] as String? ?? '',
      hbbsAddress: json['hbbsAddress'] as String? ?? '',
      hbbrAddress: json['hbbrAddress'] as String? ?? '',
      serverAddress: json['serverAddress'] as String? ?? '',
    );
  }
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
          message = 'API 地址和绑定码不能为空';
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
        showToast('绑定成功');
        close();
      } catch (error) {
        setState(() {
          isInProgress = false;
          message = error.toString();
        });
      }
    }

    return CustomAlertDialog(
      title: Text('绑定企业设备'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: apiController,
            decoration: const InputDecoration(
              labelText: '管理后台 API',
              hintText: 'http://127.0.0.1:4000',
            ),
          ).workaroundFreezeLinuxMint(),
          const SizedBox(height: 12),
          TextField(
            controller: codeController,
            decoration: const InputDecoration(
              labelText: '绑定码',
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
  if (apiBase.endsWith('/')) {
    return apiBase.substring(0, apiBase.length - 1);
  }
  return apiBase;
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
  return '绑定失败';
}

Future<String> applyPrivateDeviceConfig(
  String apiBase,
  PrivateDeviceConfig config,
) async {
  if (config.remoteId.isEmpty ||
      config.unattendedPassword.isEmpty ||
      config.hbbsAddress.isEmpty) {
    throw Exception('绑定配置不完整');
  }

  await bind.mainSetOption(key: 'private-management-api', value: apiBase);
  await bind.mainSetOption(
    key: 'custom-rendezvous-server',
    value: config.hbbsAddress,
  );
  await bind.mainSetOption(key: 'relay-server', value: config.hbbrAddress);
  await bind.mainSetOption(key: kOptionApproveMode, value: 'password');
  await bind.mainSetOption(
    key: kOptionVerificationMethod,
    value: kUsePermanentPassword,
  );

  final passwordOk = await bind.mainSetPermanentPasswordWithResult(
    password: config.unattendedPassword,
  );
  if (!passwordOk) {
    throw Exception('无人值守密码设置失败');
  }

  final currentId = await bind.mainGetMyId();
  if (currentId == config.remoteId) {
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
    return 'Timed out';
  }
  return status;
}
