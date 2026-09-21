#include "third_party/blink/renderer/core/tainting/taint_util.h"

#include <string>
#include <utility>
#include <vector>

#include "taint/Taint.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "v8/include/v8-function.h"
#include "v8/include/v8-script.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/tainting/taint_config.h"
#include "third_party/blink/renderer/core/tainting/taint_report.h"
#include "third_party/blink/renderer/core/tainting/xpath_generator.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/string_resource.h"
#include "third_party/blink/renderer/platform/wtf/text/string_impl.h"
#include "v8/include/v8-isolate.h"
#include "v8/include/v8-primitive.h"
#include "v8/include/v8-value.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/dom/events/custom_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "v8/include/v8-context.h"
#include "v8/include/v8-exception.h"
#include "v8/include/v8-object.h"

namespace blink {

namespace {

std::u16string ToU16(const String& str) {
  return str.Impl() ? str.Impl()->ToU16String() : std::u16string();
}

TaintOperation BuildOperation(const char* name, const Vector<String>& args) {
  std::vector<std::u16string> converted;
  converted.reserve(args.size());
  for (const String& arg : args) {
    converted.push_back(ToU16(arg));
  }
  return TaintOperation(name, GetTaintLocation(), std::move(converted));
}

void OverlaySource(String& str, TaintOperation op) {
  op.setSource();
  str.Impl()->Taint().overlay(0u, str.length(), op);
}

String DescribeElement(const Node* node) {
  if (!node) {
    return String();
  }
  String xpath = GenerateXPath(node);
  if (!xpath.empty()) {
    return xpath;
  }
  return node->nodeName();
}

StringResourceBase* V8ResourceOf(v8::Isolate* isolate,
                                 v8::Local<v8::String> value) {
  if (value.IsEmpty()) {
    return nullptr;
  }
  v8::String::Encoding encoding;
  v8::String::ExternalStringResourceBase* resource =
      value->GetExternalStringResourceBase(isolate, &encoding);
  if (!resource) {
    return nullptr;
  }
  if (encoding == v8::String::ONE_BYTE_ENCODING) {
    return static_cast<StringResource8Base*>(resource);
  }
  return static_cast<StringResource16Base*>(resource);
}

}  // namespace

bool GetV8StringTaint(v8::Isolate* isolate,
                      v8::Local<v8::String> value,
                      StringTaint& out) {
  StringResourceBase* resource = V8ResourceOf(isolate, value);
  if (!resource) {
    return value->GetTaint(isolate, &out);
  }
  StringImpl* impl = resource->GetWTFString().Impl();
  if (!impl) {
    return value->GetTaint(isolate, &out);
  }
  out = impl->Taint();
  return true;
}

void SetV8StringTaint(v8::Isolate* isolate,
                      v8::Local<v8::String> value,
                      const StringTaint& taint) {
  StringResourceBase* resource = V8ResourceOf(isolate, value);
  if (!resource) {
    value->SetTaint(isolate, taint);
    return;
  }
  if (StringImpl* impl = resource->GetWTFString().Impl()) {
    impl->SetTaint(taint);
  } else {
    value->SetTaint(isolate, taint);
  }
}

TaintLocation GetTaintLocation() {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (!isolate) {
    return TaintLocation();
  }
  if (!isolate->InContext()) {
    return v8::String::GetFallbackTaintLocation(isolate);
  }
  ExecutionContext* context = CurrentExecutionContext(isolate);
  if (!context) {
    return v8::String::GetFallbackTaintLocation(isolate);
  }
  SourceLocation* location = CaptureSourceLocation(context);
  if (!location || location->IsUnknown()) {
    return v8::String::GetFallbackTaintLocation(isolate);
  }
  TaintMd5 hash = {};
  return TaintLocation(ToU16(location->Url()), location->LineNumber(),
                       location->ColumnNumber(), 0u, 0u, 0u, hash,
                       ToU16(location->Function()));
}

TaintOperation GetTaintOperation(const char* name) {
  return TaintOperation(name, GetTaintLocation());
}

void MarkTaintSource(String& str, const char* name) {
  if (!TaintIsSourceActive(name) || !str.Impl() || !str.length()) {
    return;
  }
  OverlaySource(str, GetTaintOperation(name));
}

void MarkTaintSource(String& str, const char* name, const String& arg) {
  if (!TaintIsSourceActive(name) || !str.Impl() || !str.length()) {
    return;
  }
  Vector<String> args;
  args.push_back(arg);
  OverlaySource(str, BuildOperation(name, args));
}

void MarkTaintSource(String& str, const char* name, const Vector<String>& args) {
  if (!TaintIsSourceActive(name) || !str.Impl() || !str.length()) {
    return;
  }
  OverlaySource(str, BuildOperation(name, args));
}

void MarkTaintSourceElement(String& str, const char* name, const Node* node) {
  if (!TaintIsSourceActive(name) || !str.Impl() || !str.length()) {
    return;
  }
  Vector<String> args;
  args.push_back(DescribeElement(node));
  OverlaySource(str, BuildOperation(name, args));
}

void MarkTaintSourceAttribute(String& str,
                              const char* name,
                              const Element* element,
                              const String& attr) {
  if (element && str.Impl() && str.length()) {
    const TaintList& taint_list = element->GetSelectorTaintFlowList();
    if (taint_list.hasTaint()) {
      str.Impl()->Taint().overlay(0u, str.length(), *taint_list.begin());
    }
  }
  if (!TaintIsSourceActive(name) || !str.Impl() || !str.length()) {
    return;
  }
  Vector<String> args;
  args.push_back(attr);
  OverlaySource(str, BuildOperation(name, args));
}

void MarkTaintSource(ScriptState* script_state,
                     v8::Local<v8::String> value,
                     const char* name) {
  if (!TaintIsSourceActive(name)) {
    return;
  }
  v8::Isolate* isolate = script_state->GetIsolate();
  StringResourceBase* resource = V8ResourceOf(isolate, value);
  if (!resource) {
    if (value.IsEmpty() || value->Length() == 0) {
      return;
    }
    TaintOperation op = GetTaintOperation(name);
    op.setSource();
    StringTaint taint;
    taint.overlay(0u, static_cast<uint32_t>(value->Length()), op);
    value->SetTaint(isolate, taint);
    return;
  }
  StringImpl* impl = resource->GetWTFString().Impl();
  if (!impl || !impl->length()) {
    return;
  }
  TaintOperation op = GetTaintOperation(name);
  op.setSource();
  impl->Taint().overlay(0u, impl->length(), op);
}

void MarkTaintSource(ScriptState* script_state,
                     v8::Local<v8::Value> value,
                     const char* name) {
  if (!TaintIsSourceActive(name)) {
    return;
  }
  if (value.IsEmpty() || !value->IsString()) {
    return;
  }
  MarkTaintSource(script_state, value.As<v8::String>(), name);
}

void MarkTaintSource(TaintFlow& flow, const char* name, const Node* node) {
  if (!TaintIsSourceActive(name)) {
    return;
  }
  Vector<String> args;
  args.push_back(DescribeElement(node));
  TaintOperation op = BuildOperation(name, args);
  op.setSource();
  flow.extend(op);
}

void MarkTaintSource(TaintFlow& flow, const char* name, const String& arg) {
  if (!TaintIsSourceActive(name)) {
    return;
  }
  Vector<String> args;
  args.push_back(arg);
  flow.extend(BuildOperation(name, args));
}

void MarkTaintOperation(String& str, const char* name) {
  if (!str.IsTainted()) {
    return;
  }
  str.Impl()->Taint().extend(GetTaintOperation(name));
}

void MarkTaintOperation(String& str,
                        const char* name,
                        const Vector<String>& args) {
  if (!str.IsTainted()) {
    return;
  }
  str.Impl()->Taint().extend(BuildOperation(name, args));
}

void MarkTaintOperation(StringTaint& taint, const char* name) {
  taint.extend(GetTaintOperation(name));
}

void ReportTaintSink(const String& str, const char* name) {
  if (!str.IsTainted()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
  str.Impl()->Taint().extend(GetTaintOperation(name));
  ReportTaintFlow(name, str, str.Impl()->Taint());
}

void ReportTaintSink(const String& str, const char* name, const String& arg) {
  if (!str.IsTainted()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
  Vector<String> args;
  args.push_back(arg);
  str.Impl()->Taint().extend(BuildOperation(name, args));
  ReportTaintFlow(name, str, str.Impl()->Taint());
}

void ReportTaintSink(const String& str, const char* name, const Node* node) {
  if (!str.IsTainted()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
  Vector<String> args;
  args.push_back(DescribeElement(node));
  str.Impl()->Taint().extend(BuildOperation(name, args));
  ReportTaintFlow(name, str, str.Impl()->Taint());
}

void ReportTaintSink(ScriptState* script_state,
                     v8::Local<v8::Value> value,
                     const char* name) {
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
  if (value.IsEmpty() || !value->IsString()) {
    return;
  }
  StringTaint taint;
  if (!GetV8StringTaint(script_state->GetIsolate(), value.As<v8::String>(),
                        taint)) {
    return;
  }
  if (!taint.hasTaint()) {
    return;
  }
  taint.extend(GetTaintOperation(name));
  SetV8StringTaint(script_state->GetIsolate(), value.As<v8::String>(), taint);
  ReportTaintFlow(
      name, ToCoreString(script_state->GetIsolate(), value.As<v8::String>()),
      taint);
}

void DispatchTaintReportEvent(const char* sink_name,
                              const String& value,
                              const StringTaint& taint) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (!isolate || !isolate->InContext()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  ExecutionContext* context = CurrentExecutionContext(isolate);
  auto* window = DynamicTo<LocalDOMWindow>(context);
  if (!window) {
    return;
  }
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  ScriptState::Scope scope(script_state);
  v8::Local<v8::Context> v8_context = script_state->GetContext();
  StringTaint reported = taint;
  reported.extend(GetTaintOperation(sink_name));
  v8::Local<v8::String> v8_str = V8String(isolate, value);
  v8_str->SetTaint(isolate, reported);
  v8::TryCatch try_catch(isolate);
  static const char kReportBody[] =
      "if (typeof window !== 'undefined' && typeof document !== 'undefined') {\n"
      "    var t = window;\n"
      "    if (location.protocol == 'javascript:' || location.protocol == 'data:' || location.protocol == 'about:') {\n"
      "        t = parent.window;\n"
      "    }\n"
      "    var pl;\n"
      "    try {\n"
      "        pl = parent.location.href;\n"
      "    } catch (e) {\n"
      "        pl = 'different origin';\n"
      "    }\n"
      "    var timestamp = -1;\n"
      "    try {\n"
      "        timestamp = Date.now();\n"
      "    } catch (e) {\n"
      "        timestamp = -2;\n"
      "    }\n"
      "    var e = document.createEvent('CustomEvent');\n"
      "    var info = {\n"
      "        subframe: t !== window,\n"
      "        loc: location.href,\n"
      "        parentloc: pl,\n"
      "        referrer: document.referrer,\n"
      "        str: str,\n"
      "        sink: sink,\n"
      "        stack: stack,\n"
      "        timestamp: timestamp\n"
      "    }\n"
      "    e.initCustomEvent('__taintreport', true, false, info);\n"
      "    t.dispatchEvent(e);\n"
      "    return info;\n"
      "} else {\n"
      "    return undefined;\n"
      "}\n";
  v8::ScriptOrigin origin(V8String(isolate, "taint_reporting.js"));
  v8::ScriptCompiler::Source source(V8String(isolate, kReportBody), origin);
  v8::Local<v8::String> arg_names[3] = {V8String(isolate, "str"),
                                        V8String(isolate, "sink"),
                                        V8String(isolate, "stack")};
  v8::Local<v8::Function> report;
  if (!v8::ScriptCompiler::CompileFunction(v8_context, &source, 3, arg_names)
           .ToLocal(&report)) {
    return;
  }
  v8::Local<v8::Value> argv[3] = {v8_str, V8String(isolate, sink_name),
                                  v8::Undefined(isolate)};
  v8::Local<v8::Value> result;
  if (!V8ScriptRunner::CallFunction(report, context, v8::Undefined(isolate), 3,
                                    argv, isolate)
           .ToLocal(&result)) {
    return;
  }
}

}  // namespace blink
