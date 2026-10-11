[English](README.md) | [العربية](README.ar.md)

[![الترخيص](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![إصدار GitHub](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![نجوم GitHub](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![تفريعات GitHub](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![المساهمون على GitHub](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![متابعة @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
مشروع **ghidraMCP** هو خادم لبروتوكول سياق النموذج (Model Context Protocol - MCP) يتيح للنماذج اللغوية الكبيرة (LLMs) إجراء الهندسة العكسية للتطبيقات والبرمجيات بشكل ذاتي ومستقل. يوفّر الخادم العديد من الأدوات والوظائف البرمجية المستمدة من صميم إمكانيات منصة Ghidra لعملاء بروتوكول MCP.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# الميزات
خادم MCP + ملحق برمجي لمنصة Ghidra (Ghidra Plugin)

- فك التجميع (Decompilation) وتحليل الملفات والبرمجيات الثنائية داخل منصة Ghidra.
- إعادة تسمية الدوال وعناصر البيانات تلقائياً.
- سرد الدوال (Methods)، والفئات (Classes)، وعمليات الاستيراد (Imports)، وعمليات التصدير (Exports).

# التثبيت

## المتطلبات الأساسية
- تثبيت منصة [Ghidra](https://ghidra-sre.org)
- بايثون 3 (Python 3)
- حزمة تطوير برمجيات بروتوكول سياق النموذج لبايثون [MCP SDK](https://github.com/modelcontextprotocol/python-sdk)

## منصة Ghidra
أولاً، قم بتنزيل أحدث [إصدار (Release)](https://github.com/LaurieWired/GhidraMCP/releases) من هذا المستودع. يحتوي هذا الإصدار على ملحق Ghidra وعميل MCP المكتوب بلغة بايثون. بعد ذلك، يمكنك استيراد الملحق مباشرةً إلى Ghidra:

1. شغّل منصة Ghidra.
2. اختر `File` -> `Install Extensions`.
3. انقر فوق زر الإضافة `+`.
4. حدد ملف `GhidraMCP-1-2.zip` (أو الإصدار الذي قمت بتنزيله) من مجلد التنزيلات.
5. أعد تشغيل منصة Ghidra.
6. تأكد من تفعيل ملحق `GhidraMCPPlugin` عبر المسار: `File` -> `Configure` -> `Developer`.
7. *(اختياري)*: قم بتهيئة المنفذ (Port) في Ghidra عبر: `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`.

دليل التثبيت المرئي (فيديو):


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## عملاء بروتوكول سياق النموذج (MCP Clients)

من الناحية النظرية، ينبغي أن يعمل أي عميل يدعم بروتوكول MCP مع ghidraMCP. فيما يلي ثلاثة أمثلة للتكامل:

## المثال 1: تطبيق Claude Desktop
لتهيئة Claude Desktop كعميل لـ Ghidra MCP، انتقل إلى:
`Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json`
وأضف الإعدادات التالية:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

أو كخيار بديل، يمكنك تعديل هذا الملف مباشرةً:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

عنوان IP والمنفذ الخاصان بالخادم قابلان للتخصيص ويجب تعيينهما للإشارة إلى مثيل Ghidra المستهدف. وإذا لم يتم تحديدهما، فسيتم استخدام القيمة الافتراضية `localhost:8080`.

## المثال 2: إضافة Cline
لاستخدام GhidraMCP مع [Cline](https://cline.bot)، يتطلب ذلك تشغيل خادم MCP يدوياً أيضاً. قم أولاً بتشغيل الأمر التالي:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

المعامل الوحيد *الإلزامي* هو وسيط النقل (`--transport`). إذا تُركت المعاملات الأخرى دون تحديد، فستعتمد القيم الافتراضية الموضحة أعلاه. بمجرد تشغيل خادم MCP، افتح Cline وحدد `MCP Servers` في الجزء العلوي.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

ثم اختر `Remote Servers` وأضف الإعدادات التالية، مع التأكد من مطابقة الرابط لمضيف ومنفذ MCP:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## المثال 3: أداة 5ire
من الأدوات الأخرى التي تدعم بروتوكول MCP وتوفر نماذج متعددة في الخلفية أداة [5ire](https://github.com/nanbingxyz/5ire). لتهيئة GhidraMCP، افتح 5ire وانتقل إلى `Tools` -> `New` وقم بضبط الإعدادات التالية:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# البناء من المصدر (Building from Source)
1. انسخ الملفات التالية من مجلد تثبيت Ghidra الخاص بك إلى المجلد `lib/` داخل هذا المشروع:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. قم بالبناء باستخدام Maven عبر تشغيل:

`mvn clean package assembly:single`

يحتوي ملف ZIP المُنشأ على ملحق Ghidra المترجم وموارده. هذه الملفات مطلوبة لكي تتمكن منصة Ghidra من التعرف على الامتداد الجديد:

- `lib/GhidraMCP.jar`
- `extensions.properties`
- `Module.manifest`
