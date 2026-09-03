#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_UTIL_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_UTIL_H_

#include "taint/Taint.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8-forward.h"

namespace blink {

class Node;
class Element;
class ScriptState;

CORE_EXPORT bool GetV8StringTaint(v8::Isolate* isolate,
                                  v8::Local<v8::String> value,
                                  StringTaint& out);
CORE_EXPORT void SetV8StringTaint(v8::Isolate* isolate,
                                  v8::Local<v8::String> value,
                                  const StringTaint& taint);

CORE_EXPORT TaintLocation GetTaintLocation();
CORE_EXPORT TaintOperation GetTaintOperation(const char* name);

CORE_EXPORT void MarkTaintSource(String& str, const char* name);
CORE_EXPORT void MarkTaintSource(String& str, const char* name, const String& arg);
CORE_EXPORT void MarkTaintSource(String& str,
                                 const char* name,
                                 const Vector<String>& args);
CORE_EXPORT void MarkTaintSourceElement(String& str,
                                        const char* name,
                                        const Node* node);
CORE_EXPORT void MarkTaintSourceAttribute(String& str,
                                          const char* name,
                                          const Element* element,
                                          const String& attr);
CORE_EXPORT void MarkTaintSource(ScriptState* script_state,
                                 v8::Local<v8::Value> value,
                                 const char* name);
CORE_EXPORT void MarkTaintSource(ScriptState* script_state,
                                 v8::Local<v8::String> value,
                                 const char* name);
CORE_EXPORT void MarkTaintSource(TaintFlow& flow,
                                 const char* name,
                                 const Node* node);

CORE_EXPORT void MarkTaintOperation(String& str, const char* name);
CORE_EXPORT void MarkTaintOperation(String& str,
                                    const char* name,
                                    const Vector<String>& args);
CORE_EXPORT void MarkTaintOperation(StringTaint& taint, const char* name);

CORE_EXPORT void ReportTaintSink(const String& str, const char* name);
CORE_EXPORT void ReportTaintSink(const String& str,
                                 const char* name,
                                 const String& arg);
CORE_EXPORT void ReportTaintSink(const String& str,
                                 const char* name,
                                 const Node* node);
CORE_EXPORT void ReportTaintSink(ScriptState* script_state,
                                 v8::Local<v8::Value> value,
                                 const char* name);

CORE_EXPORT void DispatchTaintReportEvent(const char* sink_name,
                                          const String& value,
                                          const StringTaint& taint);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_UTIL_H_
