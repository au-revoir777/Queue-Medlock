import 'package:flutter/material.dart';

void main() {
  runApp(const MedLockMobileApp());
}

class MedLockMobileApp extends StatelessWidget {
  const MedLockMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MedLock Mesh Mobile',
      home: Scaffold(
        appBar: AppBar(title: const Text('MedLock Mesh')),
        body: const Padding(
          padding: EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Doctor Secure Client', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              SizedBox(height: 12),
              Text('• Local secure key store (placeholder)'),
              Text('• Offline encrypted queue (placeholder)'),
              Text('• Encrypted push notifications (placeholder)'),
            ],
          ),
        ),
      ),
    );
  }
}
