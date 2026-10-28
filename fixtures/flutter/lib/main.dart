import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

void configure(HttpClient client) {
  client.badCertificateCallback = (cert, host, port) => true;
}

Future<void> saveToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', 'session');
}
