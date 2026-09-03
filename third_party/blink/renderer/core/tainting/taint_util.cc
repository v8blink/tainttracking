#include "third_party/blink/renderer/core/tainting/taint_util.h"

#include <string>
#include <utility>
#include <vector>

#include "taint/Taint.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
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
  if (!isolate || !isolate->InContext()) {
    return TaintLocation();
  }
  ExecutionContext* context = CurrentExecutionContext(isolate);
  if (!context) {
    return TaintLocation();
  }
  SourceLocation* location = CaptureSourceLocation(context);
  if (!location || location->IsUnknown()) {
    return TaintLocation();
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
                              const Element*,
                              const String& attr) {
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
  ReportTaintFlow(name, str, str.Impl()->Taint());
}

void ReportTaintSink(const String& str, const char* name, const String&) {
  if (!str.IsTainted()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
  ReportTaintFlow(name, str, str.Impl()->Taint());
}

void ReportTaintSink(const String& str, const char* name, const Node*) {
  if (!str.IsTainted()) {
    return;
  }
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    return;
  }
  if (!TaintIsSinkActive(name)) {
    return;
  }
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
  v8::Local<v8::Object> detail = v8::Object::New(isolate);
  detail
      ->Set(v8_context, v8::String::NewFromUtf8Literal(isolate, "str"), v8_str)
      .Check();
  detail
      ->Set(v8_context, v8::String::NewFromUtf8Literal(isolate, "sink"),
            v8::String::NewFromUtf8(isolate, sink_name).ToLocalChecked())
      .Check();
  CustomEvent* event = CustomEvent::Create();
  event->initCustomEvent(script_state, AtomicString("__taintreport"), true,
                         false, ScriptValue(isolate, detail));
  v8::TryCatch try_catch(isolate);
  window->DispatchEvent(*event);
}

}  // namespace blink
